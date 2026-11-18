#!/usr/bin/env python3
"""L2X Panel — load + fault-tolerance test for many concurrent online clients.

Simulates N (default 500) clients that:
  1) refresh subscriptions concurrently,
  2) stay online via a single local xray-core (one SOCKS per client),
  3) generate periodic traffic so the panel marks them online,
  4) survive chaos: reconnect storms, sub bursts, xray restart, staggered join.

Requirements
  - Panel API token with clients + server scopes
  - Local ``xray`` (or ``xray.exe``) for the hold/online phase
  - ``curl`` for SOCKS traffic (or set --traffic-url and rely on curl)

Examples
  # Prepare 500 test clients, hold 10 min, chaos every 60s, then cleanup:
  python tools/loadtest_online.py \\
    --base https://panel.example.com \\
    --token l2x_xxx \\
    --clients 500 --duration 600 --chaos 60 --cleanup

  # Only subscription storm (no xray):
  python tools/loadtest_online.py --base … --token … --phase sub --clients 500

  # Reuse already created loadtest-* clients:
  python tools/loadtest_online.py --base … --token … --reuse --duration 300

Env fallbacks: L2X_BASE, L2X_TOKEN, L2X_XRAY
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import random
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# --------------------------------------------------------------------------- CLI / constants

DEFAULT_PREFIX = "loadtest"
DEFAULT_TRAFFIC_URL = "https://1.1.1.1/cdn-cgi/trace"
UA = "l2x-loadtest/1.0"


@dataclass
class ClientRow:
    email: str
    uuid: str = ""
    sub_url: str = ""
    link: str = ""  # first vless/vmess/… share link
    socks_port: int = 0
    ok_sub: int = 0
    fail_sub: int = 0
    ok_traffic: int = 0
    fail_traffic: int = 0
    last_err: str = ""


@dataclass
class Stats:
    t0: float = field(default_factory=time.monotonic)
    sub_ok: int = 0
    sub_fail: int = 0
    sub_lat_ms: list[float] = field(default_factory=list)
    traffic_ok: int = 0
    traffic_fail: int = 0
    chaos_events: int = 0
    online_samples: list[tuple[float, int]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def note_err(self, msg: str, limit: int = 40) -> None:
        if len(self.errors) < limit:
            self.errors.append(msg)


# --------------------------------------------------------------------------- HTTP (stdlib)

def _http(
    method: str,
    url: str,
    *,
    token: str | None = None,
    data: dict | None = None,
    timeout: float = 30.0,
    headers: dict[str, str] | None = None,
) -> tuple[int, bytes, float]:
    body = None
    hdrs = {"User-Agent": UA, "Accept": "*/*"}
    if token:
        hdrs["Authorization"] = f"Bearer {token}"
    if headers:
        hdrs.update(headers)
    if data is not None:
        body = json.dumps(data).encode()
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method.upper())
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return int(resp.status), raw, (time.monotonic() - t0) * 1000
    except urllib.error.HTTPError as e:
        raw = e.read() if e.fp else b""
        return int(e.code), raw, (time.monotonic() - t0) * 1000
    except Exception as e:
        raise RuntimeError(f"{method} {url}: {e}") from e


def api(base: str, token: str, path: str, *, method: str = "GET", data: dict | None = None, timeout: float = 45.0) -> Any:
    url = base.rstrip("/") + "/panel/api/" + path.lstrip("/")
    # Panel parses JSON on every POST — always send an object body.
    if method.upper() == "POST" and data is None:
        data = {}
    code, raw, _ = _http(method, url, token=token, data=data, timeout=timeout)
    try:
        payload = json.loads(raw.decode("utf-8", "replace") or "{}")
    except ValueError:
        raise RuntimeError(f"API {path}: non-json HTTP {code}: {raw[:200]!r}")
    if code >= 400 or not payload.get("success", True):
        raise RuntimeError(f"API {path}: HTTP {code} {payload.get('msg') or raw[:200]!r}")
    return payload.get("obj")


def api_retry(
    base: str,
    token: str,
    path: str,
    *,
    method: str = "GET",
    data: dict | None = None,
    timeout: float = 120.0,
    attempts: int = 5,
) -> Any:
    last: Exception | None = None
    for i in range(attempts):
        try:
            return api(base, token, path, method=method, data=data, timeout=timeout)
        except Exception as e:
            last = e
            wait = min(30.0, 1.5 * (i + 1))
            print(f"  ! API {method} {path} try {i + 1}/{attempts}: {e} — sleep {wait:.1f}s")
            time.sleep(wait)
    raise RuntimeError(str(last) if last else "api failed")


# --------------------------------------------------------------------------- subscription / link parse

def decode_sub_body(raw: bytes) -> list[str]:
    text = raw.decode("utf-8", "replace").strip()
    if not text:
        return []
    # plain multi-line
    if "://" in text and "\n" in text:
        return [ln.strip() for ln in text.splitlines() if "://" in ln]
    if "://" in text and text.count("://") == 1 and "\n" not in text:
        return [text]
    # base64 blob
    pad = "=" * (-len(text) % 4)
    try:
        dec = base64.b64decode(text + pad).decode("utf-8", "replace")
    except Exception:
        return [ln.strip() for ln in text.splitlines() if "://" in ln]
    return [ln.strip() for ln in dec.splitlines() if "://" in ln]


def parse_share_link(link: str) -> dict[str, Any] | None:
    """Minimal VLESS/VMess/Trojan URI → fields needed for an xray outbound."""
    link = (link or "").strip()
    if not link or "://" not in link:
        return None
    try:
        scheme, rest = link.split("://", 1)
    except ValueError:
        return None
    scheme = scheme.lower()
    if scheme not in ("vless", "trojan", "ss"):
        return None
    # strip fragment
    rest, _, frag = rest.partition("#")
    userinfo, _, hostpart = rest.partition("@")
    if not hostpart:
        return None
    hostport, _, q = hostpart.partition("?")
    if hostport.startswith("["):
        # [ipv6]:port
        br = hostport.find("]")
        host = hostport[1:br]
        port = int(hostport[br + 2 :] or "443")
    else:
        host, _, ports = hostport.partition(":")
        port = int(ports or "443")
    qs = urllib.parse.parse_qs(q, keep_blank_values=True)
    one = {k: (v[0] if v else "") for k, v in qs.items()}
    uuid = userinfo
    if scheme == "trojan":
        uuid = userinfo  # password
    network = (one.get("type") or one.get("network") or "tcp").lower()
    security = (one.get("security") or ("tls" if one.get("tls") == "tls" else "none")).lower()
    if security in ("", "none") and one.get("sni"):
        security = "tls"
    return {
        "scheme": scheme,
        "uuid": uuid,
        "host": host,
        "port": port,
        "network": network,
        "security": security,
        "sni": one.get("sni") or one.get("host") or host,
        "host_header": one.get("host") or "",
        "path": one.get("path") or "/",
        "mode": one.get("mode") or "",
        "service_name": one.get("serviceName") or one.get("service_name") or "",
        "fp": one.get("fp") or "chrome",
        "alpn": one.get("alpn") or "",
        "pbk": one.get("pbk") or "",
        "sid": one.get("sid") or "",
        "spx": one.get("spx") or "",
        "flow": one.get("flow") or "",
        "encryption": one.get("encryption") or "none",
        "remark": urllib.parse.unquote(frag) if frag else "",
        "raw": link,
    }


def outbound_from_link(tag: str, p: dict[str, Any]) -> dict[str, Any]:
    stream: dict[str, Any] = {"network": p["network"]}
    sec = p["security"]
    if sec in ("tls", "reality"):
        tls: dict[str, Any] = {
            "serverName": p["sni"] or p["host"],
            "fingerprint": p["fp"] or "chrome",
            "allowInsecure": False,
        }
        if p["alpn"]:
            tls["alpn"] = [x.strip() for x in p["alpn"].split(",") if x.strip()]
        if sec == "reality" or p["pbk"]:
            tls["realitySettings"] = {
                "publicKey": p["pbk"],
                "shortId": p["sid"] or "",
                "spiderX": p["spx"] or "",
            }
            stream["security"] = "reality"
        else:
            stream["security"] = "tls"
        stream["tlsSettings"] = tls
    else:
        stream["security"] = "none"

    net = p["network"]
    if net in ("ws", "websocket"):
        stream["network"] = "ws"
        stream["wsSettings"] = {"path": p["path"] or "/", "headers": {"Host": p["host_header"] or p["sni"] or p["host"]}}
    elif net in ("httpupgrade", "http_upgrade"):
        stream["network"] = "httpupgrade"
        stream["httpupgradeSettings"] = {"path": p["path"] or "/", "host": p["host_header"] or p["sni"] or p["host"]}
    elif net in ("xhttp", "splithttp"):
        stream["network"] = "xhttp"
        xh: dict[str, Any] = {"path": p["path"] or "/", "host": p["host_header"] or p["sni"] or p["host"]}
        if p["mode"]:
            xh["mode"] = p["mode"]
        stream["xhttpSettings"] = xh
    elif net == "grpc":
        stream["network"] = "grpc"
        stream["grpcSettings"] = {
            "serviceName": p["service_name"] or (p["path"] or "").strip("/"),
            "multiMode": p["mode"] == "multi",
        }
    elif net == "h2":
        stream["network"] = "h2"
        stream["httpSettings"] = {"path": p["path"] or "/", "host": [p["host_header"] or p["sni"] or p["host"]]}
    else:
        stream["network"] = "tcp"

    if p["scheme"] == "vless":
        user = {"id": p["uuid"], "encryption": p["encryption"] or "none", "level": 0}
        if p["flow"]:
            user["flow"] = p["flow"]
        return {
            "tag": tag,
            "protocol": "vless",
            "settings": {"vnext": [{"address": p["host"], "port": int(p["port"]), "users": [user]}]},
            "streamSettings": stream,
        }
    if p["scheme"] == "trojan":
        return {
            "tag": tag,
            "protocol": "trojan",
            "settings": {"servers": [{"address": p["host"], "port": int(p["port"]), "password": p["uuid"]}]},
            "streamSettings": stream,
        }
    raise ValueError(f"unsupported scheme {p['scheme']}")


def build_client_xray_config(rows: list[ClientRow], parsed: list[dict[str, Any]], socks_base: int) -> dict[str, Any]:
    inbounds = []
    outbounds = []
    rules = []
    for i, (row, p) in enumerate(zip(rows, parsed)):
        port = socks_base + i
        row.socks_port = port
        tag = f"c{i}"
        inbounds.append({
            "tag": f"socks-{i}",
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "socks",
            "settings": {"udp": True, "auth": "noauth"},
        })
        outbounds.append(outbound_from_link(tag, p))
        rules.append({"type": "field", "inboundTag": [f"socks-{i}"], "outboundTag": tag})
    outbounds.append({"tag": "direct", "protocol": "freedom", "settings": {}})
    outbounds.append({"tag": "block", "protocol": "blackhole", "settings": {}})
    return {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"domainStrategy": "AsIs", "rules": rules},
    }


# --------------------------------------------------------------------------- helpers

def find_xray(explicit: str | None) -> str | None:
    if explicit:
        return explicit if Path(explicit).exists() or shutil.which(explicit) else None
    for name in ("xray", "xray.exe"):
        p = shutil.which(name)
        if p:
            return p
    return None


def pct(ok: int, fail: int) -> str:
    total = ok + fail
    if not total:
        return "n/a"
    return f"{100.0 * ok / total:.1f}%"


def summary_lat(samples: list[float]) -> str:
    if not samples:
        return "n/a"
    s = sorted(samples)
    def q(p: float) -> float:
        return s[min(len(s) - 1, int(len(s) * p))]
    return f"p50={q(0.5):.0f}ms p95={q(0.95):.0f}ms p99={q(0.99):.0f}ms max={s[-1]:.0f}ms"


# --------------------------------------------------------------------------- prepare / cleanup

def list_loadtest_clients(base: str, token: str, prefix: str) -> list[dict]:
    clients = api(base, token, "clients/list") or []
    return [c for c in clients if str(c.get("email") or "").startswith(prefix + "-")]


def load_subs_file(path: str, n: int) -> list[ClientRow]:
    """File formats: one sub URL per line, or email<TAB>sub_url."""
    rows: list[ClientRow] = []
    for i, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "\t" in line:
            email, sub = line.split("\t", 1)
        elif " " in line and not line.startswith("http"):
            email, sub = line.split(None, 1)
        else:
            email, sub = f"{DEFAULT_PREFIX}-file-{i:04d}", line
        rows.append(ClientRow(email=email.strip(), sub_url=sub.strip()))
        if len(rows) >= n:
            break
    if not rows:
        raise SystemExit(f"no entries in {path}")
    print(f"[prepare] loaded {len(rows)} subs from {path}")
    return rows


def _row_from_public(c: dict) -> ClientRow:
    return ClientRow(
        email=str(c.get("email") or ""),
        uuid=str(c.get("uuid") or ""),
        sub_url=str(c.get("sub_url") or ""),
    )


def prepare_clients(base: str, token: str, n: int, prefix: str, group_id: str, reuse: bool) -> list[ClientRow]:
    existing = list_loadtest_clients(base, token, prefix)
    rows: list[ClientRow] = []
    if reuse and existing:
        existing = sorted(existing, key=lambda c: str(c.get("email") or ""))[:n]
        rows = [_row_from_public(c) for c in existing]
        print(f"[prepare] reuse {len(rows)} existing {prefix}-* clients")
        if len(rows) >= n:
            return rows[:n]

    need = n - len(rows)
    start = 1
    have = {r.email for r in rows}
    while f"{prefix}-{start:04d}" in have:
        start += 1

    payload: dict[str, Any] = {
        "count": need,
        "prefix": prefix,
        "start": start,
        "enabled": True,
        "sub_enabled": True,
        "comment": "loadtest auto",
        "limit_ip": 0,
        "outbound": "direct",
    }
    if group_id:
        payload["group_id"] = group_id

    # Prefer bulkAdd (one xray apply). Fallback: one-by-one with retries.
    print(f"[prepare] bulkAdd {need} clients (prefix={prefix}, start={start})…")
    try:
        obj = api_retry(base, token, "clients/bulkAdd", method="POST", data=payload, timeout=600.0, attempts=4)
        batch = obj if isinstance(obj, list) else []
        rows.extend(_row_from_public(c) for c in batch)
        print(f"[prepare] bulkAdd ok: +{len(batch)} (total {len(rows)})")
        if len(rows) >= n:
            return rows[:n]
    except Exception as e:
        print(f"[prepare] bulkAdd unavailable ({e}) — falling back to single add")

    print(f"[prepare] creating {n - len(rows)} clients one-by-one…")
    have = {r.email for r in rows}
    while len(rows) < n:
        idx = len(rows) + 1
        while f"{prefix}-{idx:04d}" in have:
            idx += 1
        email = f"{prefix}-{idx:04d}"
        one = {
            "email": email,
            "enabled": True,
            "sub_enabled": True,
            "comment": "loadtest auto",
            "limit_ip": 0,
            "outbound": "direct",
        }
        if group_id:
            one["group_id"] = group_id
        try:
            obj = api_retry(base, token, "clients/add", method="POST", data=one, timeout=180.0, attempts=6)
            rows.append(_row_from_public(obj or {"email": email}))
        except Exception as e:
            # Apply may drop the HTTP response after the client was already saved.
            time.sleep(2.0)
            found = next((c for c in list_loadtest_clients(base, token, prefix) if c.get("email") == email), None)
            if found:
                print(f"  ~ add {email}: response lost but client exists")
                rows.append(_row_from_public(found))
            else:
                print(f"  !! give up on {email}: {e}")
                raise
        have.add(email)
        if len(rows) % 25 == 0 or len(rows) == n:
            print(f"  … {len(rows)}/{n}")
        time.sleep(0.4)
    return rows[:n]


def cleanup_clients(base: str, token: str, prefix: str) -> int:
    print(f"[cleanup] bulkDelete prefix={prefix}-* …")
    try:
        obj = api_retry(
            base, token, "clients/bulkDelete", method="POST",
            data={"prefix": prefix + "-"}, timeout=300.0, attempts=4,
        )
        n = int((obj or {}).get("removed") or 0)
        print(f"[cleanup] deleted {n}")
        return n
    except Exception as e:
        print(f"[cleanup] bulkDelete unavailable ({e}) — single deletes")
    victims = list_loadtest_clients(base, token, prefix)
    print(f"[cleanup] deleting {len(victims)} {prefix}-* clients…")
    n = 0
    for c in victims:
        email = str(c.get("email") or "")
        try:
            api_retry(
                base, token, f"clients/delete/{urllib.parse.quote(email, safe='')}",
                method="POST", data={}, timeout=120.0, attempts=4,
            )
            n += 1
        except Exception as ex:
            print(f"  ! delete {email}: {ex}")
        time.sleep(0.2)
    print(f"[cleanup] deleted {n}")
    return n


# --------------------------------------------------------------------------- phases

async def fetch_one_sub(row: ClientRow, sem: asyncio.Semaphore, stats: Stats, timeout: float) -> None:
    if not row.sub_url:
        stats.sub_fail += 1
        row.fail_sub += 1
        row.last_err = "empty sub_url"
        return
    url = row.sub_url + ("&" if "?" in row.sub_url else "?") + "format=plain"
    async with sem:
        loop = asyncio.get_running_loop()
        try:
            code, raw, ms = await loop.run_in_executor(
                None, lambda: _http("GET", url, timeout=timeout, headers={"Accept": "text/plain"})
            )
            stats.sub_lat_ms.append(ms)
            if code >= 400:
                raise RuntimeError(f"HTTP {code}")
            links = decode_sub_body(raw)
            if not links:
                raise RuntimeError("empty subscription")
            row.link = links[0]
            row.ok_sub += 1
            stats.sub_ok += 1
        except Exception as e:
            row.fail_sub += 1
            stats.sub_fail += 1
            row.last_err = str(e)
            stats.note_err(f"sub {row.email}: {e}")


async def phase_sub(rows: list[ClientRow], stats: Stats, concurrency: int, rounds: int, timeout: float) -> None:
    print(f"[sub] {len(rows)} clients × {rounds} round(s), concurrency={concurrency}")
    sem = asyncio.Semaphore(concurrency)
    for r in range(rounds):
        t0 = time.monotonic()
        await asyncio.gather(*(fetch_one_sub(row, sem, stats, timeout) for row in rows))
        ok = sum(1 for x in rows if x.link)
        print(f"  round {r + 1}/{rounds}: links={ok}/{len(rows)}  "
              f"ok={stats.sub_ok} fail={stats.sub_fail}  {summary_lat(stats.sub_lat_ms[-len(rows):])}  "
              f"{time.monotonic() - t0:.1f}s")


def phase_build_xray(rows: list[ClientRow], socks_base: int) -> tuple[dict[str, Any], list[ClientRow]]:
    ready: list[ClientRow] = []
    parsed: list[dict[str, Any]] = []
    for row in rows:
        p = parse_share_link(row.link)
        if not p:
            row.last_err = "unparsed link"
            continue
        ready.append(row)
        parsed.append(p)
    if not ready:
        raise SystemExit("no parseable share links — cannot start xray hold phase")
    cfg = build_client_xray_config(ready, parsed, socks_base)
    print(f"[xray] config for {len(ready)} clients, socks {socks_base}…{socks_base + len(ready) - 1}")
    return cfg, ready


async def traffic_one(row: ClientRow, url: str, stats: Stats, timeout: float) -> None:
    if not row.socks_port:
        return
    cmd = [
        "curl", "-sS", "-o", os.devnull, "-m", str(int(timeout)),
        "--socks5-hostname", f"127.0.0.1:{row.socks_port}",
        url,
    ]
    loop = asyncio.get_running_loop()

    def run() -> int:
        try:
            return subprocess.run(cmd, capture_output=True, timeout=timeout + 2).returncode
        except Exception:
            return 99

    rc = await loop.run_in_executor(None, run)
    if rc == 0:
        row.ok_traffic += 1
        stats.traffic_ok += 1
    else:
        row.fail_traffic += 1
        stats.traffic_fail += 1
        row.last_err = f"curl rc={rc}"
        stats.note_err(f"traffic {row.email}: curl rc={rc}")


async def poll_online(base: str, token: str, prefix: str, stats: Stats, stop: asyncio.Event, every: float) -> None:
    loop = asyncio.get_running_loop()
    while not stop.is_set():
        try:
            online = await loop.run_in_executor(None, lambda: api(base, token, "inbounds/onlines", timeout=20.0))
            # online: {email: [ip, …]}
            n = 0
            if isinstance(online, dict):
                for email in online:
                    if str(email).startswith(prefix + "-") or "~" in str(email) and str(email).split("~", 1)[0].startswith(prefix + "-"):
                        n += 1
            # also total panel online
            st = await loop.run_in_executor(None, lambda: api(base, token, "server/status", timeout=20.0))
            total = int((st or {}).get("online") or 0)
            stats.online_samples.append((time.monotonic() - stats.t0, n))
            print(f"  [online] loadtest≈{n}  panel_total={total}")
        except Exception as e:
            stats.note_err(f"online poll: {e}")
            print(f"  [online] poll error: {e}")
        try:
            await asyncio.wait_for(stop.wait(), timeout=every)
        except asyncio.TimeoutError:
            pass


@dataclass
class ProcBox:
    proc: subprocess.Popen | None = None


async def chaos_loop(
    rows: list[ClientRow],
    stats: Stats,
    stop: asyncio.Event,
    every: float,
    sub_conc: int,
    traffic_url: str,
    box: ProcBox,
    xray_bin: str | None,
    cfg_path: Path | None,
) -> None:
    """Fault injection: sub burst, traffic storm, optional local xray restart."""
    if every <= 0:
        return
    modes = ["sub_burst", "traffic_storm", "sleep_gap"]
    if xray_bin and cfg_path:
        modes.append("restart_local_xray")
    while not stop.is_set():
        try:
            await asyncio.wait_for(stop.wait(), timeout=every)
            break
        except asyncio.TimeoutError:
            pass
        if stop.is_set():
            break
        mode = random.choice(modes)
        stats.chaos_events += 1
        print(f"  [chaos] #{stats.chaos_events} → {mode}")
        if mode == "sub_burst":
            await phase_sub(rows, stats, concurrency=sub_conc, rounds=1, timeout=20.0)
        elif mode == "traffic_storm":
            await asyncio.gather(*(traffic_one(r, traffic_url, stats, 15.0) for r in rows))
            print(f"    traffic_ok={stats.traffic_ok} fail={stats.traffic_fail}")
        elif mode == "sleep_gap":
            print("    pause traffic 8s (connections should idle / drop)")
            await asyncio.sleep(8)
        elif mode == "restart_local_xray" and box.proc is not None and cfg_path is not None and xray_bin:
            print("    restarting local xray (client reconnect storm)…")
            old = box.proc
            try:
                old.terminate()
            except Exception:
                try:
                    old.kill()
                except Exception:
                    pass
            try:
                old.wait(timeout=8)
            except Exception:
                try:
                    old.kill()
                except Exception:
                    pass
            box.proc = subprocess.Popen(
                [xray_bin, "run", "-c", str(cfg_path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            await asyncio.sleep(2)
            await asyncio.gather(*(traffic_one(r, traffic_url, stats, 20.0) for r in rows[: min(50, len(rows))]))


async def phase_hold(
    base: str,
    token: str,
    prefix: str,
    rows: list[ClientRow],
    stats: Stats,
    *,
    duration: float,
    tick: float,
    traffic_url: str,
    concurrency: int,
    chaos: float,
    xray_bin: str,
    socks_base: int,
    poll_every: float,
) -> None:
    cfg, ready = phase_build_xray(rows, socks_base)
    tmp = Path(tempfile.mkdtemp(prefix="l2x-loadtest-"))
    cfg_path = tmp / "client.json"
    cfg_path.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[hold] writing {cfg_path} ; starting xray for {duration:.0f}s")
    box = ProcBox(subprocess.Popen(
        [xray_bin, "run", "-c", str(cfg_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ))
    stop = asyncio.Event()
    poll_task = asyncio.create_task(poll_online(base, token, prefix, stats, stop, poll_every))
    chaos_task = asyncio.create_task(
        chaos_loop(ready, stats, stop, chaos, concurrency, traffic_url, box, xray_bin, cfg_path)
    )

    # ramp-up: staggered first traffic
    print("[hold] ramp-up traffic…")
    batch = max(1, len(ready) // 10)
    for i in range(0, len(ready), batch):
        chunk = ready[i : i + batch]
        await asyncio.gather(*(traffic_one(r, traffic_url, stats, 25.0) for r in chunk))
        print(f"  ramp {min(i + batch, len(ready))}/{len(ready)}  "
              f"traffic ok/fail={stats.traffic_ok}/{stats.traffic_fail}")
        await asyncio.sleep(0.4)

    deadline = time.monotonic() + duration
    try:
        while time.monotonic() < deadline:
            sample = ready if len(ready) <= concurrency else random.sample(ready, concurrency)
            await asyncio.gather(*(traffic_one(r, traffic_url, stats, 20.0) for r in sample))
            alive = sum(1 for r in ready if r.ok_traffic > r.fail_traffic)
            left = deadline - time.monotonic()
            print(f"  tick alive≈{alive}/{len(ready)}  ok/fail={stats.traffic_ok}/{stats.traffic_fail}  "
                  f"left={left:.0f}s")
            if box.proc is None or box.proc.poll() is not None:
                print("  ! local xray exited — restarting")
                box.proc = subprocess.Popen(
                    [xray_bin, "run", "-c", str(cfg_path)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                stats.chaos_events += 1
            await asyncio.sleep(tick)
    finally:
        stop.set()
        await asyncio.gather(poll_task, chaos_task, return_exceptions=True)
        if box.proc and box.proc.poll() is None:
            box.proc.terminate()
            try:
                box.proc.wait(timeout=5)
            except Exception:
                box.proc.kill()
        print(f"[hold] stopped; temp config kept at {cfg_path} (delete manually if needed)")


# --------------------------------------------------------------------------- report

def print_report(rows: list[ClientRow], stats: Stats) -> None:
    elapsed = time.monotonic() - stats.t0
    print("\n========== LOADTEST REPORT ==========")
    print(f"elapsed: {elapsed:.1f}s   clients: {len(rows)}")
    print(f"sub:     ok={stats.sub_ok} fail={stats.sub_fail} success={pct(stats.sub_ok, stats.sub_fail)}  {summary_lat(stats.sub_lat_ms)}")
    print(f"traffic: ok={stats.traffic_ok} fail={stats.traffic_fail} success={pct(stats.traffic_ok, stats.traffic_fail)}")
    print(f"chaos events: {stats.chaos_events}")
    if stats.online_samples:
        vals = [n for _, n in stats.online_samples]
        print(f"online(loadtest*): min={min(vals)} max={max(vals)} last={vals[-1]}  "
              f"mean={statistics.mean(vals):.1f}")
    bad = [r for r in rows if r.fail_sub or r.fail_traffic]
    if bad:
        print(f"clients with errors: {len(bad)} (showing up to 15)")
        for r in bad[:15]:
            print(f"  {r.email}: sub={r.ok_sub}/{r.fail_sub} traffic={r.ok_traffic}/{r.fail_traffic}  {r.last_err}")
    if stats.errors:
        print("sample errors:")
        for e in stats.errors[:12]:
            print(f"  - {e}")
    print("=====================================\n")


# --------------------------------------------------------------------------- main

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="L2X 500-client online load + fault-tolerance test")
    ap.add_argument("--base", default=os.environ.get("L2X_BASE", ""), help="https://panel-host (no base_path)")
    ap.add_argument("--token", default=os.environ.get("L2X_TOKEN", ""), help="API Bearer token l2x_…")
    ap.add_argument("--clients", type=int, default=500, help="number of concurrent clients (default 500)")
    ap.add_argument("--prefix", default=DEFAULT_PREFIX, help="email prefix for test clients")
    ap.add_argument("--group-id", default="", help="optional group_id for created clients")
    ap.add_argument("--reuse", action="store_true", help="reuse existing prefix-* clients")
    ap.add_argument("--subs-file", default="", help="skip API create: file with sub URLs (or email\\tsub_url)")
    ap.add_argument("--cleanup", action="store_true", help="delete prefix-* clients at the end")
    ap.add_argument("--cleanup-only", action="store_true", help="only delete prefix-* clients and exit")
    ap.add_argument("--phase", choices=("all", "prepare", "sub", "hold"), default="all",
                    help="all=prepare+sub+hold; sub=HTTP only; hold needs xray")
    ap.add_argument("--duration", type=float, default=300.0, help="hold phase seconds (default 300)")
    ap.add_argument("--tick", type=float, default=15.0, help="traffic keep-alive interval")
    ap.add_argument("--chaos", type=float, default=0.0, help="chaos interval seconds (0=off)")
    ap.add_argument("--concurrency", type=int, default=80, help="max parallel sub/traffic workers")
    ap.add_argument("--sub-rounds", type=int, default=2, help="subscription fetch rounds")
    ap.add_argument("--socks-base", type=int, default=18000, help="first local SOCKS port")
    ap.add_argument("--traffic-url", default=DEFAULT_TRAFFIC_URL, help="URL fetched via each SOCKS")
    ap.add_argument("--poll-every", type=float, default=20.0, help="panel online poll interval")
    ap.add_argument("--xray", default=os.environ.get("L2X_XRAY", ""), help="path to xray binary")
    ap.add_argument("--skip-prepare", action="store_true", help="do not create clients (need --reuse)")
    args = ap.parse_args(argv)

    if not args.base or not args.token:
        ap.error("--base and --token are required (or L2X_BASE / L2X_TOKEN)")
    args.base = args.base.rstrip("/")

    if args.cleanup_only:
        cleanup_clients(args.base, args.token, args.prefix)
        return 0

    # sanity
    try:
        st = api(args.base, args.token, "server/status")
        print(f"[panel] online={st.get('online')} xray={((st.get('xray') or {}).get('running'))}")
    except Exception as e:
        print(f"FATAL: cannot reach API: {e}", file=sys.stderr)
        return 2

    stats = Stats()
    rows: list[ClientRow] = []

    try:
        if args.subs_file:
            rows = load_subs_file(args.subs_file, args.clients)
        else:
            reuse = args.reuse or args.skip_prepare or args.phase in ("sub", "hold")
            if args.phase == "all" and not args.reuse and not args.skip_prepare:
                reuse = False
            rows = prepare_clients(
                args.base, args.token, args.clients, args.prefix, args.group_id, reuse=reuse,
            )

        if args.phase == "prepare":
            print(f"[prepare] done: {len(rows)} clients")
            return 0

        if args.phase in ("all", "sub", "hold"):
            asyncio.run(phase_sub(rows, stats, args.concurrency, args.sub_rounds, timeout=25.0))

        if args.phase in ("all", "hold"):
            xray_bin = find_xray(args.xray or None)
            if not xray_bin:
                print("FATAL: xray binary not found (install xray or pass --xray). "
                      "Subscription phase already finished — use --phase sub to skip hold.", file=sys.stderr)
                print_report(rows, stats)
                return 3
            if not shutil.which("curl"):
                print("FATAL: curl not found (needed for SOCKS traffic)", file=sys.stderr)
                return 3
            missing = sum(1 for r in rows if not r.link)
            if missing:
                print(f"[hold] warning: {missing} clients without links")
            asyncio.run(phase_hold(
                args.base, args.token, args.prefix, rows, stats,
                duration=args.duration,
                tick=args.tick,
                traffic_url=args.traffic_url,
                concurrency=args.concurrency,
                chaos=args.chaos,
                xray_bin=xray_bin,
                socks_base=args.socks_base,
                poll_every=args.poll_every,
            ))
    finally:
        print_report(rows, stats)
        if args.cleanup:
            cleanup_clients(args.base, args.token, args.prefix)

    # exit code: fail if success rate too low
    if stats.sub_ok + stats.sub_fail > 0 and stats.sub_ok / max(1, stats.sub_ok + stats.sub_fail) < 0.85:
        return 10
    if stats.traffic_ok + stats.traffic_fail > 0 and stats.traffic_ok / max(1, stats.traffic_ok + stats.traffic_fail) < 0.70:
        return 11
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        raise SystemExit(130)
