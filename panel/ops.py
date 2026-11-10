"""Host operations: Xray versions, geo files, logs, BBR, ACME certs, backups, WARP/NordVPN."""
from __future__ import annotations

import io
import ipaddress
import json
import os
import platform
import re
import shutil
import subprocess
import threading
import time
import urllib.request
import zipfile
from pathlib import Path

XRAY_BIN = Path(os.environ.get("XRAY_BIN", "/usr/local/bin/xray"))
GEO_DIR = Path(os.environ.get("XRAY_LOCATION_ASSET", "/usr/local/share/xray"))
CERT_DIR = Path(os.environ.get("L2XPANEL_CERT_DIR", "/etc/l2xpanel/certs"))
UA = {"User-Agent": "l2xpanel"}

JOBS: dict[str, dict] = {}

PANEL_SLOT_FILE = Path("/etc/l2xpanel/panel_slot")
UPDATE_UNIT = "l2xpanel-update"
UPDATE_LOG = Path("/var/log/l2xpanel-update.log")
UPDATE_RC = Path("/run/l2xpanel-update.rc")
# Shell snippet: resolve the active panel unit at run time (slot may change after scheduling).
ACTIVE_UNIT_SH = ('u=l2xpanel; [ "$(tr -d "[:space:]" </etc/l2xpanel/panel_slot 2>/dev/null)" = next ] '
                  '&& u=l2xpanel-next')


def active_panel_unit() -> str:
    """systemd unit currently serving the panel (dual-slot: l2xpanel or l2xpanel-next)."""
    try:
        if PANEL_SLOT_FILE.read_text(encoding="utf-8").strip() == "next":
            return "l2xpanel-next"
    except OSError:
        pass
    return "l2xpanel"


def _in_panel_cgroup() -> bool:
    """True when this process lives inside a panel unit — stopping that unit would kill our children."""
    try:
        cg = Path("/proc/self/cgroup").read_text(encoding="utf-8")
    except OSError:
        return False
    return "l2xpanel.service" in cg or "l2xpanel-next.service" in cg


def _run_detached(cmd: list[str], env: dict, timeout: int = 900) -> dict:
    """Run cmd in a transient systemd unit so it survives the panel unit being stopped.

    The dual-slot cutover stops the old panel unit; with KillMode=control-group a plain
    child of the panel would be killed mid-update and leave the panel down.
    """
    passthrough = ("L2X_BRANCH", "SKIP_XRAY", "XRAY_VERSION", "L2X_REPO", "PATH", "HOME")
    try:
        UPDATE_RC.unlink(missing_ok=True)
    except OSError:
        pass
    quoted = " ".join("'" + c.replace("'", "'\\''") + "'" for c in cmd)
    script = (f"{quoted} >{UPDATE_LOG} 2>&1; rc=$?; echo $rc >{UPDATE_RC}; exit $rc")
    run = ["systemd-run", f"--unit={UPDATE_UNIT}", "--collect", "--quiet",
           "-p", "KillMode=process", "-p", f"RuntimeMaxSec={timeout}"]
    for k in passthrough:
        if env.get(k):
            run.append(f"--setenv={k}={env[k]}")
    run += ["/bin/bash", "-c", script]
    started = _run(run, 30, env=env)
    if not started["ok"]:
        err = (started.get("stderr") or "").strip()
        if "already" in err.lower() or "exists" in err.lower():
            return {"ok": False, "code": 1, "stdout": "", "stderr": "обновление панели уже выполняется"}
        return started
    deadline = time.time() + timeout + 30
    while time.time() < deadline:
        if UPDATE_RC.is_file():
            break
        time.sleep(2)
    try:
        log = UPDATE_LOG.read_text(encoding="utf-8", errors="replace")
    except OSError:
        log = ""
    try:
        code = int(UPDATE_RC.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return {"ok": False, "code": 124, "stdout": log, "stderr": "таймаут обновления панели"}
    return {"ok": code == 0, "code": code, "stdout": log, "stderr": ""}


def _run(
    cmd: list[str] | str,
    timeout: int = 120,
    shell: bool = False,
    env: dict | None = None,
    cwd: str | None = None,
) -> dict:
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, shell=shell, env=env, cwd=cwd,
        )
        return {"ok": p.returncode == 0, "code": p.returncode, "stdout": p.stdout, "stderr": p.stderr}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "code": 127, "stdout": "", "stderr": str(exc)}


def _http(url: str, timeout: int = 30, data: bytes | None = None, headers: dict | None = None, method: str | None = None) -> bytes:
    req = urllib.request.Request(url, data=data, headers={**UA, **(headers or {})}, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def start_job(name: str, fn, *args) -> str:
    job_id = f"{name}-{int(time.time())}"
    JOBS[job_id] = {"name": name, "status": "running", "log": "", "started": time.time()}
    # Preserve panel operator (login+IP) across the worker thread for TG notifications
    actor = ""
    try:
        import tgbot as _tg
        actor = _tg.get_actor()
    except Exception:
        actor = ""

    def runner():
        tok = None
        try:
            import tgbot as _tg
            tok = _tg.set_actor(actor)
        except Exception:
            tok = None
        try:
            res = fn(*args)
            JOBS[job_id]["status"] = "done" if res.get("ok") else "failed"
            JOBS[job_id]["log"] = res.get("log") or res.get("error") or json.dumps(res, ensure_ascii=False)[:4000]
        except Exception as exc:  # noqa: BLE001
            JOBS[job_id]["status"] = "failed"
            JOBS[job_id]["log"] = str(exc)
        finally:
            if tok is not None:
                try:
                    import tgbot as _tg
                    _tg.reset_actor(tok)
                except Exception:
                    pass

    threading.Thread(target=runner, daemon=True).start()
    return job_id


# ---------------------------------------------------------------- xray core

def xray_releases(limit: int = 15) -> list[str]:
    try:
        data = json.loads(_http(f"https://api.github.com/repos/XTLS/Xray-core/releases?per_page={limit}", 20))
        return [r["tag_name"] for r in data if r.get("tag_name")]
    except Exception:
        return []


def version_tuple(v: str) -> tuple[int, ...]:
    """'v26.10.31' / '26.10.31' → (26, 10, 31); non-numeric parts are ignored."""
    nums = []
    for part in str(v or "").lstrip("vV").split("."):
        digits = "".join(ch for ch in part if ch.isdigit())
        if digits == "":
            break
        nums.append(int(digits))
    return tuple(nums)


def normalize_tag(version: str) -> str:
    v = str(version or "").strip()
    if not v:
        return ""
    return v if v.startswith("v") or v.startswith("V") else f"v{v}"


PANEL_REPO = os.environ.get("L2X_REPO_API", "eliot-voodi/l2x-panel")


def panel_releases(limit: int = 20, *, include_prerelease: bool = False) -> list[dict]:
    """GitHub panel releases newest-first: [{tag, url, published, prerelease, notes}]."""
    try:
        data = json.loads(_http(f"https://api.github.com/repos/{PANEL_REPO}/releases?per_page={limit}", 20))
    except Exception:
        return []
    out = []
    for r in data:
        if r.get("draft") or not r.get("tag_name"):
            continue
        if r.get("prerelease") and not include_prerelease:
            continue
        out.append({
            "tag": r["tag_name"],
            "url": r.get("html_url") or "",
            "published": r.get("published_at") or "",
            "prerelease": bool(r.get("prerelease")),
            "notes": (r.get("body") or "")[:2000],
        })
    return out


def panel_latest(include_prerelease: bool = False) -> dict:
    """Newest L2X Panel release on GitHub."""
    releases = panel_releases(15, include_prerelease=include_prerelease)
    if not releases:
        try:
            raw = _http(f"https://raw.githubusercontent.com/{PANEL_REPO}/main/VERSION", 15).decode().strip()
            return {"ok": True, "tag": raw if raw.startswith("v") else f"v{raw}", "url": "", "published": "",
                    "prerelease": False, "notes": ""}
        except Exception as exc:
            return {"ok": False, "error": f"нет релизов: {exc}"}
    best = max(releases, key=lambda r: version_tuple(r["tag"]))
    return {
        "ok": True,
        "tag": best["tag"],
        "url": best.get("url") or "",
        "published": best.get("published") or "",
        "prerelease": bool(best.get("prerelease")),
        "notes": best.get("notes") or "",
    }


def update_panel(version: str = "", *, skip_xray: bool | None = None, full: bool = False) -> dict:
    """Run install.sh --update/--update-full [TAG] (keeps data).

    Fast path (default, nginx mode): dual-slot cutover — download into the inactive slot,
    start the second service, /health, one nginx upstream flip, then stop the old unit.
    The previous slot tree is kept for the next rollback/update. ``full=True`` also
    refreshes apt/xray/nginx before the same cutover.

    ``version`` pins/rolls back to a GitHub release tag (e.g. v1.9.72).
    """
    tag = normalize_tag(version)
    env = os.environ.copy()
    if tag:
        env["L2X_BRANCH"] = tag
        if skip_xray is None:
            skip_xray = True
    if skip_xray or not full:
        env["SKIP_XRAY"] = "1"
    elif "SKIP_XRAY" in env:
        env.pop("SKIP_XRAY", None)

    flag = "--update-full" if full else "--update"
    if Path("/usr/local/bin/l2x").exists():
        # l2x update [TAG] → fast; l2x update --full [TAG] → full
        cmd = ["/usr/local/bin/l2x", "update"]
        if full:
            cmd.append("--full")
        if tag:
            cmd.append(tag)
    else:
        args = flag + (f" {tag}" if tag else "")
        script = (
            "curl -fsSL https://raw.githubusercontent.com/eliot-voodi/l2x-panel/main/install.sh "
            f"| bash -s -- {args}"
        )
        cmd = ["bash", "-lc", script]
    if _in_panel_cgroup() and shutil.which("systemd-run"):
        r = _run_detached(cmd, env, timeout=900)
    else:
        r = _run(cmd, timeout=900, env=env)
    log = (r.get("stdout") or "")[-3000:] + ("\n" + (r.get("stderr") or "")[-1000:] if r.get("stderr") else "")
    # install.sh dies (nonzero) after successful rollback — treat as failed update
    rolled = "восстановлена" in (log or "").lower() or "rolled back" in (log or "").lower()
    ver = ""
    try:
        ver = Path("/opt/l2xpanel/VERSION").read_text(encoding="utf-8").strip().splitlines()[0]
    except OSError:
        pass
    ok = bool(r.get("ok")) and not rolled
    return {
        "ok": ok,
        "log": log or f"exit {r.get('code')}",
        "version": ver,
        "requested": tag or "latest",
        "rolled_back": rolled,
        "error": "" if ok else (r.get("stderr") or log[-500:] or "update failed"),
    }


def rollback_panel(version: str) -> dict:
    """Install a specific older (or any) panel release tag."""
    tag = normalize_tag(version)
    if not tag:
        return {"ok": False, "error": "укажите версию панели (например v1.9.72)"}
    return update_panel(tag, skip_xray=True)


def xray_latest(include_prerelease: bool = False) -> dict:
    """Newest Xray-core release on GitHub: {ok, tag, url, published, prerelease, notes} or {ok: False, error}."""
    try:
        data = json.loads(_http("https://api.github.com/repos/XTLS/Xray-core/releases?per_page=20", 20))
    except Exception as exc:
        return {"ok": False, "error": f"GitHub: {exc}"}
    best = None
    for r in data:
        if r.get("draft") or not r.get("tag_name"):
            continue
        if r.get("prerelease") and not include_prerelease:
            continue
        if best is None or version_tuple(r["tag_name"]) > version_tuple(best["tag_name"]):
            best = r
    if not best:
        return {"ok": False, "error": "нет подходящих релизов"}
    return {
        "ok": True,
        "tag": best["tag_name"],
        "url": best.get("html_url") or "",
        "published": best.get("published_at") or "",
        "prerelease": bool(best.get("prerelease")),
        "notes": (best.get("body") or "")[:4000],
    }


def _xray_asset() -> str:
    m = platform.machine().lower()
    if m in ("aarch64", "arm64"):
        return "Xray-linux-arm64-v8a.zip"
    if m.startswith("armv7"):
        return "Xray-linux-arm32-v7a.zip"
    return "Xray-linux-64.zip"


def _xray_bin_version(path: Path) -> str:
    r = _run([str(path), "version"], 15)
    if not r.get("ok"):
        return ""
    # "Xray 26.10.31 (Xray, Penetrates Everything.) ..."
    line = (r.get("stdout") or "").splitlines()[0] if r.get("stdout") else ""
    parts = line.split()
    for i, p in enumerate(parts):
        if p.lower() == "xray" and i + 1 < len(parts):
            return parts[i + 1].lstrip("vV")
        if p[:1].isdigit():
            return p.lstrip("vV")
    return ""


def xray_backup_info() -> dict:
    """Info about the previous binary saved as xray.bak during the last install."""
    backup = XRAY_BIN.with_suffix(".bak")
    meta = XRAY_BIN.with_suffix(".bak.version")
    if not backup.is_file():
        return {"ok": False, "exists": False, "version": "", "path": str(backup)}
    ver = ""
    if meta.is_file():
        try:
            ver = meta.read_text(encoding="utf-8").strip().splitlines()[0].lstrip("vV")
        except OSError:
            ver = ""
    if not ver:
        ver = _xray_bin_version(backup)
    return {
        "ok": True,
        "exists": True,
        "version": ver,
        "path": str(backup),
        "mtime": int(backup.stat().st_mtime),
    }


def _activate_xray_binary(new_bin: Path, *, label: str) -> dict:
    """Replace live binary with new_bin (already executable), test config, restart."""
    cfg = os.environ.get("XRAY_CONFIG", "/etc/xray/config.json")
    log = [label]
    if Path(cfg).exists():
        check = _run([str(new_bin), "run", "-test", "-config", cfg], 60)
        if not check["ok"]:
            return {
                "ok": False,
                "error": "конфиг не проходит xray -test:\n" + (check["stderr"] or check["stdout"])[-1500:],
                "log": "\n".join(log),
            }
        log.append("config test: ok")
    # Swap: keep current as .bak so rollback can be undone
    backup = XRAY_BIN.with_suffix(".bak")
    meta = XRAY_BIN.with_suffix(".bak.version")
    had_old = XRAY_BIN.exists()
    prev_ver = _xray_bin_version(XRAY_BIN) if had_old else ""
    tmp_live = XRAY_BIN.with_suffix(".swap")
    if had_old:
        shutil.copy2(XRAY_BIN, tmp_live)
    os.replace(new_bin, XRAY_BIN)
    if had_old and tmp_live.exists():
        os.replace(tmp_live, backup)
        try:
            meta.write_text(prev_ver or "", encoding="utf-8")
        except OSError:
            pass
    r = _run(["systemctl", "restart", "xray"], 30)
    time.sleep(3)
    active = _run(["systemctl", "is-active", "xray"])["stdout"].strip() == "active"
    if not (r["ok"] and active):
        if had_old and backup.exists():
            os.replace(backup, XRAY_BIN)
            _run(["systemctl", "restart", "xray"], 30)
        return {
            "ok": False,
            "error": f"Xray не запустился после {label}\n{(r.get('stderr') or '')[-800:]}",
            "log": "\n".join(log),
        }
    ver = _xray_bin_version(XRAY_BIN)
    log.append(f"active version={ver or '?'}")
    return {"ok": True, "log": "\n".join(log), "version": ver}


def install_xray(version: str) -> dict:
    version = normalize_tag(version)
    if not version:
        return {"ok": False, "error": "не указана версия Xray"}
    url = f"https://github.com/XTLS/Xray-core/releases/download/{version}/{_xray_asset()}"
    try:
        blob = _http(url, 180)
    except Exception as exc:
        return {"ok": False, "error": f"download {url}: {exc}"}
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        data = z.read("xray")
    tmp = XRAY_BIN.with_suffix(".new")
    tmp.write_bytes(data)
    os.chmod(tmp, 0o755)
    test = _run([str(tmp), "version"])
    if not test["ok"]:
        tmp.unlink(missing_ok=True)
        return {"ok": False, "error": test["stderr"] or "new binary does not run"}
    res = _activate_xray_binary(tmp, label=f"downloaded {version}")
    if res.get("ok"):
        res["version"] = version.lstrip("vV")
    return res


def rollback_xray(version: str = "") -> dict:
    """Roll Xray back to ``version`` from GitHub, or to local ``xray.bak`` if version empty."""
    tag = normalize_tag(version)
    if tag:
        return install_xray(tag)
    info = xray_backup_info()
    if not info.get("exists"):
        return {"ok": False, "error": "нет локального xray.bak — укажите версию из GitHub releases"}
    bak = Path(info["path"])
    # Copy bak to .new so _activate can move current → bak (undo path)
    tmp = XRAY_BIN.with_suffix(".new")
    shutil.copy2(bak, tmp)
    os.chmod(tmp, 0o755)
    label = f"rollback from bak ({info.get('version') or 'unknown'})"
    return _activate_xray_binary(tmp, label=label)


def xray_control(action: str) -> dict:
    if action not in ("start", "stop", "restart"):
        return {"ok": False, "error": "bad action", "stderr": "bad action"}
    return _run(["systemctl", action, "xray"], 30)


# ---------------------------------------------------------------- geo

GEO_SOURCES = {
    "geoip.dat": "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat",
    "geosite.dat": "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat",
}

# Optional packs — use in routes as ext:filename.dat:tag
GEO_PACKS = {
    "russia": {
        "title": "Russia rules (runetfreedom)",
        "hint": "ext:geoip_RU.dat:ru · ext:geosite_RU.dat:ru / category-ads-all",
        "files": [
            {"name": "geoip_RU.dat", "url": "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geoip.dat"},
            {"name": "geosite_RU.dat", "url": "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geosite.dat"},
        ],
    },
}


def update_geo(custom: list[dict] | None = None) -> dict:
    import security as sec
    GEO_DIR.mkdir(parents=True, exist_ok=True)
    log = []
    sources = dict(GEO_SOURCES)
    for item in custom or []:
        name = str(item.get("name") or "").strip()
        if name and item.get("url"):
            try:
                safe = sec.validate_outbound_url(str(item["url"]), allow_http=False)
            except ValueError as exc:
                log.append(f"{name}: BLOCKED {exc}")
                continue
            sources[name if name.endswith(".dat") else f"{name}.dat"] = safe
    ok = True
    for name, url in sources.items():
        try:
            # Built-in GitHub sources are fixed; custom already validated above
            if name not in GEO_SOURCES:
                sec.validate_outbound_url(url, allow_http=False)
            data = _http(url, 180)
            if len(data) < 1024:
                raise ValueError("file too small")
            tmp = GEO_DIR / f"{name}.tmp"
            tmp.write_bytes(data)
            os.replace(tmp, GEO_DIR / name)
            log.append(f"{name}: {len(data) // 1024} KB")
        except Exception as exc:
            ok = False
            log.append(f"{name}: ERROR {exc}")
    xr = _run(["systemctl", "restart", "xray"], 30)
    if not xr.get("ok"):
        ok = False
        log.append(f"xray restart: {xr.get('stderr') or xr.get('stdout') or 'fail'}")
    else:
        log.append("xray: restarted")
    return {"ok": ok, "log": "\n".join(log)}


def geo_files() -> list[dict]:
    if not GEO_DIR.exists():
        return []
    return [
        {"name": p.name, "size": p.stat().st_size, "mtime": int(p.stat().st_mtime)}
        for p in sorted(GEO_DIR.glob("*.dat"))
    ]


def geo_missing_core() -> list[str]:
    """Return core geoip/geosite names that are missing or empty."""
    missing = []
    for name in GEO_SOURCES:
        p = GEO_DIR / name
        if not p.is_file() or p.stat().st_size < 1024:
            missing.append(name)
    return missing


# ---------------------------------------------------------------- logs

def journal(unit: str, lines: int = 300, grep: str = "") -> str:
    cmd = ["journalctl", "-u", unit, "-n", str(lines), "--no-pager", "-o", "short-iso"]
    if grep:
        cmd += ["-g", grep]
    r = _run(cmd, 20)
    return r["stdout"] or r["stderr"]


def ensure_ports_open(ports) -> list[str]:
    """Allow inbound TCP/UDP on direct inbound ports (ufw if active, else iptables). Idempotent."""
    done: list[str] = []
    ports = sorted({int(p) for p in ports or [] if 1 <= int(p) <= 65535})
    if not ports:
        return done
    ufw = shutil.which("ufw")
    ufw_on = bool(ufw) and "Status: active" in (_run([ufw, "status"], 15).get("stdout") or "")
    ipt = shutil.which("iptables")
    for port in ports:
        if ufw_on:
            _run([ufw, "allow", str(port)], 15)
            done.append(f"ufw {port}")
            continue
        if not ipt:
            continue
        for proto in ("tcp", "udp"):
            rule = ["INPUT", "-p", proto, "--dport", str(port), "-j", "ACCEPT"]
            if not _run([ipt, "-C", *rule], 10).get("ok"):
                _run([ipt, "-I", *rule], 10)
                done.append(f"iptables {proto}/{port}")
    if done and not ufw_on and shutil.which("netfilter-persistent"):
        _run(["netfilter-persistent", "save"], 30)
    return done


def xray_debug_capture(seconds: int = 20, grep: str = "", lines: int = 400) -> dict:
    """Run Xray with loglevel=debug for a short window, return its journal, restore config."""
    import time as _time

    seconds = max(5, min(90, int(seconds or 20)))
    cfg_path = Path("/etc/xray/config.json")
    if not cfg_path.is_file():
        return {"ok": False, "error": "нет /etc/xray/config.json", "text": ""}
    original = cfg_path.read_text(encoding="utf-8")
    try:
        cfg = json.loads(original)
    except ValueError as e:
        return {"ok": False, "error": f"bad config: {e}", "text": ""}
    cfg.setdefault("log", {})["loglevel"] = "debug"
    since = _time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        cfg_path.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
        _run(["systemctl", "restart", "xray"], 30)
        _time.sleep(seconds)
    finally:
        cfg_path.write_text(original, encoding="utf-8")
        _run(["systemctl", "restart", "xray"], 30)
    cmd = ["journalctl", "-u", "xray", "--since", since, "--no-pager", "-o", "cat"]
    if grep:
        cmd += ["-g", grep]
    r = _run(cmd, 30)
    text = "\n".join((r["stdout"] or r["stderr"] or "").splitlines()[-max(50, min(3000, lines)):])
    return {"ok": True, "error": "", "text": text, "seconds": seconds}


def tail(path: str, lines: int = 300) -> str:
    p = Path(path)
    if not p.exists():
        return f"{path}: нет файла (включите access log в настройках Xray)"
    r = _run(["tail", "-n", str(lines), str(p)], 10)
    return r["stdout"]


# ---------------------------------------------------------------- BBR

PERF_SYSCTL_PATH = Path("/etc/sysctl.d/99-l2xpanel-perf.conf")
PERF_MODULES_PATH = Path("/etc/modules-load.d/l2x-perf.conf")
PERF_EPHEMERAL_LOW = 10240
# Keep in sync with tunnel/internal/netperf (Go agents on hosts without the panel).
PERF_FIXED_RESERVED = (11080, 11081, 18080, 19100)


def _mem_total_mb() -> int:
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) // 1024
    except (OSError, ValueError, IndexError):
        pass
    return 1024


def _listening_ports(min_port: int) -> set[int]:
    ports: set[int] = set()
    for name, listen_state in (("tcp", "0A"), ("tcp6", "0A"), ("udp", "07"), ("udp6", "07")):
        try:
            lines = Path(f"/proc/net/{name}").read_text().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            parts = line.split()
            if len(parts) < 4 or parts[3] != listen_state:
                continue
            try:
                port = int(parts[1].rsplit(":", 1)[1], 16)
            except (ValueError, IndexError):
                continue
            if port >= min_port:
                ports.add(port)
    return ports


def perf_sysctl_body(mem_mb: int | None = None, reserved: set[int] | None = None) -> str:
    mem = _mem_total_mb() if mem_mb is None else mem_mb
    if mem >= 3500:
        buf, ct = 67108864, 1048576
    elif mem >= 1800:
        buf, ct = 33554432, 524288
    else:
        buf, ct = 16777216, 262144
    if reserved is None:
        reserved = set(PERF_FIXED_RESERVED) | _listening_ports(PERF_EPHEMERAL_LOW)
    res = ",".join(str(p) for p in sorted(reserved))
    lines = [
        f"# managed by l2x-panel — network perf (RAM {mem} MB)",
        "net.core.default_qdisc = fq",
        "net.ipv4.tcp_congestion_control = bbr",
        f"net.core.rmem_max = {buf}",
        f"net.core.wmem_max = {buf}",
        "net.core.rmem_default = 1048576",
        "net.core.wmem_default = 1048576",
        f"net.ipv4.tcp_rmem = 4096 131072 {buf}",
        f"net.ipv4.tcp_wmem = 4096 65536 {buf}",
        "net.ipv4.udp_rmem_min = 16384",
        "net.ipv4.udp_wmem_min = 16384",
        "net.core.netdev_max_backlog = 16384",
        "net.core.somaxconn = 65535",
        "net.ipv4.tcp_max_syn_backlog = 65535",
        f"net.ipv4.ip_local_port_range = {PERF_EPHEMERAL_LOW} 65535",
    ]
    if res:
        lines.append(f"net.ipv4.ip_local_reserved_ports = {res}")
    lines += [
        "net.ipv4.tcp_notsent_lowat = 16384",
        "net.ipv4.tcp_fastopen = 3",
        "net.ipv4.tcp_slow_start_after_idle = 0",
        "net.ipv4.tcp_mtu_probing = 1",
        f"-net.netfilter.nf_conntrack_max = {ct}",
    ]
    return "\n".join(lines) + "\n"


PERF_SYSCTL_BODY = perf_sysctl_body(mem_mb=1024, reserved=set(PERF_FIXED_RESERVED))


def bbr_status() -> dict:
    cc = _run(["sysctl", "-n", "net.ipv4.tcp_congestion_control"])["stdout"].strip()
    qd = _run(["sysctl", "-n", "net.core.default_qdisc"])["stdout"].strip()
    return {"enabled": cc == "bbr", "congestion": cc, "qdisc": qd}


def bbr_set(enable: bool) -> dict:
    conf = Path("/etc/sysctl.d/99-l2x-bbr.conf")
    if enable:
        conf.write_text("net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n")
        try:
            PERF_SYSCTL_PATH.write_text(perf_sysctl_body(), encoding="utf-8")
        except OSError:
            pass
    else:
        conf.write_text("net.core.default_qdisc=fq_codel\nnet.ipv4.tcp_congestion_control=cubic\n")
    r = _run(["sysctl", "-p", str(conf)])
    if enable and PERF_SYSCTL_PATH.is_file():
        _run(["sysctl", "-e", "-p", str(PERF_SYSCTL_PATH)])
    return {"ok": r["ok"], **bbr_status(), "error": r["stderr"]}


def _physical_ifaces() -> list[str]:
    """Non-loopback NICs that have a backing device (skip veth/bridge/docker)."""
    root = Path("/sys/class/net")
    if not root.is_dir():
        return []
    out: list[str] = []
    for p in sorted(root.iterdir()):
        name = p.name
        if name == "lo" or not (p / "device").exists():
            continue
        out.append(name)
    return out


def ensure_iface_fq() -> dict:
    """Apply `tc qdisc … fq` on physical NICs.

    ``net.core.default_qdisc=fq`` only affects *new* interfaces / after reboot —
    existing eth0 often stays on fq_codel until replaced explicitly (needed for BBR).
    """
    changed: list[str] = []
    errors: list[str] = []
    for iface in _physical_ifaces():
        cur = _run(["tc", "qdisc", "show", "dev", iface])
        text = (cur.get("stdout") or "").strip()
        root = ""
        for line in text.splitlines():
            if " root" in line:
                root = line
                break
        if not root and text:
            root = text.splitlines()[0]
        # Already fq (but not fq_codel)
        if re.search(r"\bqdisc\s+fq\s", root) and "fq_codel" not in root:
            continue
        r = _run(["tc", "qdisc", "replace", "dev", iface, "root", "fq"])
        if r.get("ok"):
            changed.append(iface)
        else:
            err = (r.get("stderr") or r.get("stdout") or "tc failed").strip()
            errors.append(f"{iface}: {err}")
    return {"ok": not errors, "changed": changed, "errors": errors}


def ensure_low_ram_swap(min_ram_mb: int = 1800, size_gb: int = 2) -> dict:
    """On small VMs without swap, add a swapfile so peaks don't OOM-kill Xray/panel."""
    mem = _mem_total_mb()
    swap_total = 0
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("SwapTotal:"):
                swap_total = int(line.split()[1])
                break
    except (OSError, ValueError, IndexError):
        pass
    if mem >= min_ram_mb or swap_total > 0:
        return {"ok": True, "skipped": True, "mem_mb": mem, "swap_kb": swap_total}
    path = Path("/swapfile")
    created = False
    if not path.exists():
        # Prefer fallocate; fall back to dd
        r = _run(["fallocate", "-l", f"{size_gb}G", str(path)])
        if not r.get("ok"):
            r = _run(["dd", "if=/dev/zero", f"of={path}", "bs=1M", f"count={size_gb * 1024}", "status=none"])
            if not r.get("ok"):
                return {"ok": False, "error": r.get("stderr") or "create swapfile failed", "mem_mb": mem}
        created = True
    try:
        os.chmod(path, 0o600)
    except OSError:
        _run(["chmod", "600", str(path)])
    _run(["mkswap", str(path)])
    r = _run(["swapon", str(path)])
    if not r.get("ok") and "Device or resource busy" not in (r.get("stderr") or ""):
        return {"ok": False, "error": r.get("stderr") or "swapon failed", "mem_mb": mem, "created": created}
    fstab = Path("/etc/fstab")
    try:
        fst = fstab.read_text(encoding="utf-8") if fstab.is_file() else ""
        if "/swapfile" not in fst:
            with fstab.open("a", encoding="utf-8") as fh:
                fh.write("\n/swapfile none swap sw 0 0\n")
    except OSError as exc:
        return {"ok": False, "error": f"fstab: {exc}", "mem_mb": mem, "created": created}
    swap_conf = Path("/etc/sysctl.d/99-l2xpanel-swap.conf")
    try:
        swap_conf.write_text("vm.swappiness = 10\n", encoding="utf-8")
        _run(["sysctl", "-e", "-p", str(swap_conf)])
    except OSError:
        _run(["sysctl", "-w", "vm.swappiness=10"])
    return {"ok": True, "created": created, "mem_mb": mem, "size_gb": size_gb, "path": str(path)}


def ensure_network_perf() -> dict:
    """Idempotent: BBR, buffers, backlog, iface fq qdisc, and low-RAM swapfile."""
    body = perf_sysctl_body()
    try:
        cur = (PERF_SYSCTL_PATH.read_text(encoding="utf-8") if PERF_SYSCTL_PATH.is_file() else "")
    except OSError:
        cur = ""
    wrote = False
    if cur.strip() != body.strip():
        try:
            PERF_SYSCTL_PATH.write_text(body, encoding="utf-8")
            wrote = True
        except OSError as exc:
            return {"ok": False, "error": str(exc), **bbr_status()}
    try:
        if not PERF_MODULES_PATH.is_file():
            PERF_MODULES_PATH.parent.mkdir(parents=True, exist_ok=True)
            PERF_MODULES_PATH.write_text("tcp_bbr\n", encoding="utf-8")
    except OSError:
        pass
    _run(["modprobe", "tcp_bbr"])
    r = _run(["sysctl", "-e", "-p", str(PERF_SYSCTL_PATH)])
    fq = ensure_iface_fq()
    swap = ensure_low_ram_swap()
    st = bbr_status()
    err_parts = []
    if not r["ok"]:
        err_parts.append(r["stderr"] or "sysctl")
    if not fq.get("ok") and fq.get("errors"):
        err_parts.append("fq: " + "; ".join(fq["errors"][:3]))
    if not swap.get("ok") and swap.get("error"):
        err_parts.append("swap: " + str(swap["error"]))
    return {
        "ok": r["ok"] and st.get("enabled") and fq.get("ok", True) and swap.get("ok", True),
        "wrote": wrote,
        "fq": fq,
        "swap": swap,
        "error": "; ".join(err_parts),
        **st,
    }


# ---------------------------------------------------------------- ACME

def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


ACME_WEBROOT = Path("/var/www/l2x-acme")
# Standalone fallback: free :80 for the challenge by stopping whichever reverse proxy holds it
_PROXY_UNITS = "nginx caddy"
ACME_PRE_HOOK = (f"for s in {_PROXY_UNITS}; do systemctl is-active -q $s && systemctl stop $s "
                 "&& touch /run/l2x-acme-$s; done; true")
ACME_POST_HOOK = (f"for s in {_PROXY_UNITS}; do [ -f /run/l2x-acme-$s ] && rm -f /run/l2x-acme-$s "
                  "&& systemctl start $s; done; true")


def _acme_webroot_ready() -> bool:
    """nginx from deploy/nginx.conf serves /.well-known/acme-challenge/ from ACME_WEBROOT."""
    return ACME_WEBROOT.is_dir() and _run(["systemctl", "is-active", "nginx"])["stdout"].strip() == "active"


def issue_cert(domain: str, email: str) -> dict:
    """Let's Encrypt via acme.sh: nginx webroot when available, otherwise standalone on :80.
    Accepts a domain or a public IP."""
    domain = domain.strip().lower().strip("[]")
    if not domain or "/" in domain or " " in domain:
        return {"ok": False, "error": "bad domain"}
    is_ip = _is_ip(domain)
    if is_ip and not ipaddress.ip_address(domain).is_global:
        return {"ok": False, "error": "нужен публичный IP"}
    log = []
    # systemd starts the service without HOME, so acme.sh would otherwise install into /.acme.sh
    env = {**os.environ, "HOME": "/root"}
    acme = Path("/root/.acme.sh/acme.sh")
    email = email.strip() if "@" in (email or "") else ""
    if not acme.exists():
        r = _run("cd /tmp && curl -fsSL https://get.acme.sh | sh" + (f" -s email={email}" if email else ""), 300,
                 shell=True, env=env)
        log.append(r["stdout"][-1500:] + r["stderr"][-1500:])
        if not acme.exists():
            return {"ok": False, "log": "\n".join(log), "error": "acme.sh install failed"}
    cmd = [str(acme), "--issue", "-d", domain, "--server", "letsencrypt", "--force"]
    if _acme_webroot_ready():
        cmd += ["--webroot", str(ACME_WEBROOT)]
        log.append(f"mode: webroot {ACME_WEBROOT}")
    else:
        _run(["apt-get", "install", "-y", "socat"], 300)
        # acme.sh stores the hooks, so cron renewals free :80 the same way
        cmd += ["--standalone", "--pre-hook", ACME_PRE_HOOK, "--post-hook", ACME_POST_HOOK]
        log.append("mode: standalone")
    if is_ip:
        # Let's Encrypt issues IP certificates only with the 160-hour shortlived profile
        cmd += ["--cert-profile", "shortlived", "--days", "3"]
    r = _run(cmd, 300, env=env)
    log.append(r["stdout"][-3000:] + r["stderr"][-1500:])
    if not r["ok"]:
        return {"ok": False, "log": "\n".join(log), "error": "acme.sh issue failed"}
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    crt, key = CERT_DIR / f"{domain}.crt", CERT_DIR / f"{domain}.key"
    r2 = _run([str(acme), "--install-cert", "-d", domain, "--fullchain-file", str(crt), "--key-file", str(key),
               "--reloadcmd", "systemctl restart xray; systemctl reload nginx 2>/dev/null; "
                              f"{ACTIVE_UNIT_SH}; systemd-run --on-active=5 systemctl restart $u"],
              120, env=env)
    log.append(r2["stdout"][-1500:])
    ok = crt.exists() and key.exists()
    return {"ok": ok, "cert_file": str(crt), "key_file": str(key), "ip": is_ip, "log": "\n".join(log)}


def list_certs() -> list[dict]:
    if not CERT_DIR.exists():
        return []
    out = []
    for crt in sorted(CERT_DIR.glob("*.crt")):
        key = crt.with_suffix(".key")
        end = _run(["openssl", "x509", "-enddate", "-noout", "-in", str(crt)])["stdout"].strip().replace("notAfter=", "")
        out.append({"domain": crt.stem, "cert_file": str(crt), "key_file": str(key) if key.exists() else "", "expires": end})
    return out


# ---------------------------------------------------------------- backup

BACKUP_EXCLUDE = {"history.json"}
# Max size for a single file in promote JSON bundles (certs / DoH); larger files stay on disk backup only
PROMOTE_FILE_MAX = 8 * 1024 * 1024


def doh_dir() -> Path:
    return Path(os.environ.get("L2XPANEL_DOH_DIR", "/opt/l2xpanel/doh"))


def _safe_zip_name(name: str) -> bool:
    return bool(name) and not name.startswith("/") and ".." not in name.split("/")


def _add_tree_to_zip(z: zipfile.ZipFile, root: Path, prefix: str) -> int:
    """Write files under root into the zip as ``prefix/rel``. Returns file count."""
    if not root.is_dir():
        return 0
    n = 0
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(root).as_posix()
        if not _safe_zip_name(rel):
            continue
        z.write(p, f"{prefix}/{rel}")
        n += 1
    return n


def backups_dir(data_dir: Path) -> Path:
    """On-disk staging for Telegram / scheduled backups (deleted after successful send)."""
    d = Path(data_dir) / "backups"
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    return d


def make_backup(data_dir: Path) -> bytes:
    """Full system backup: panel data + TLS certs + DoH/Pi-hole compose volumes."""
    buf = io.BytesIO()
    counts = {"data": 0, "certs": 0, "doh": 0}
    staged = Path(data_dir) / "backups"
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(data_dir.rglob("*")):
            if not p.is_file():
                continue
            # Skip staged TG backups and restore safety copies (avoid zip-in-zip bloat)
            if p.name in BACKUP_EXCLUDE or p.name.startswith("pre-restore-"):
                continue
            try:
                if staged in p.parents or p.parent == staged:
                    continue
            except Exception:
                pass
            rel = p.relative_to(data_dir).as_posix()
            if not _safe_zip_name(rel) or rel.startswith("backups/"):
                continue
            z.write(p, rel)
            counts["data"] += 1
        counts["certs"] = _add_tree_to_zip(z, CERT_DIR, "certs")
        counts["doh"] = _add_tree_to_zip(z, doh_dir(), "doh")
        z.writestr("_meta.json", json.dumps({
            "created": int(time.time()), "app": "l2xpanel",
            "includes": ["data", "certs", "doh"], "counts": counts,
        }))
    return buf.getvalue()


def write_backup(data_dir: Path, *, name: str = "") -> dict:
    """Write backup zip under data_dir/backups/. Caller should delete after TG send."""
    stamp = time.strftime("%Y%m%d-%H%M%S")
    fname = (name or f"l2xpanel-{stamp}.zip").strip()
    if not fname.endswith(".zip"):
        fname += ".zip"
    fname = Path(fname).name  # no path traversal
    path = backups_dir(data_dir) / fname
    try:
        blob = make_backup(data_dir)
        path.write_bytes(blob)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return {"ok": True, "path": str(path), "name": fname, "size": len(blob), "bytes": blob}
    except OSError as exc:
        return {"ok": False, "error": str(exc)}


def delete_backup_file(path: str | Path) -> bool:
    try:
        p = Path(path)
        if p.is_file():
            p.unlink()
            return True
    except OSError:
        pass
    return False


def cleanup_staged_backups(data_dir: Path, *, keep_newest: int = 0) -> int:
    """Remove staged zip files in backups/. keep_newest=0 deletes all."""
    d = backups_dir(data_dir)
    files = sorted(
        (p for p in d.glob("*.zip") if p.is_file()),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    removed = 0
    for i, p in enumerate(files):
        if i < max(0, int(keep_newest or 0)):
            continue
        try:
            p.unlink()
            removed += 1
        except OSError:
            pass
    return removed


def cleanup_pre_restore(data_dir: Path, *, keep_newest: int = 1) -> int:
    """Drop old pre-restore-*.zip safety copies in the data dir."""
    files = sorted(
        (p for p in Path(data_dir).glob("pre-restore-*.zip") if p.is_file()),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    removed = 0
    for i, p in enumerate(files):
        if i < max(0, int(keep_newest or 0)):
            continue
        try:
            p.unlink()
            removed += 1
        except OSError:
            pass
    return removed


def restore_backup(data_dir: Path, blob: bytes) -> dict:
    try:
        z = zipfile.ZipFile(io.BytesIO(blob))
    except zipfile.BadZipFile:
        return {"ok": False, "error": "не zip-архив"}
    names = z.namelist()
    if "store.json" not in names:
        return {"ok": False, "error": "в архиве нет store.json"}
    safety = data_dir / f"pre-restore-{int(time.time())}.zip"
    safety.write_bytes(make_backup(data_dir))
    cleanup_pre_restore(data_dir, keep_newest=1)
    restored = {"data": 0, "certs": 0, "doh": 0}
    ddir = doh_dir()
    for name in names:
        if not _safe_zip_name(name) or name == "_meta.json" or name.startswith("pre-restore-"):
            continue
        if name.endswith("/"):
            continue
        if name.startswith("certs/"):
            target = CERT_DIR / name[len("certs/"):]
            restored["certs"] += 1
        elif name.startswith("doh/"):
            target = ddir / name[len("doh/"):]
            restored["doh"] += 1
        else:
            target = data_dir / name
            restored["data"] += 1
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(z.read(name))
        try:
            if name.endswith(".key") or name.endswith(".env") or "secret" in name.lower():
                os.chmod(target, 0o600)
        except OSError:
            pass
    # Bring Pi-hole back if compose was restored (docker may be missing on fresh hosts)
    doh_note = ""
    if restored["doh"] and (ddir / "docker-compose.yml").is_file():
        if not shutil.which("docker") and not shutil.which("docker-compose"):
            doh_note = "docker not installed — DoH files restored, start Pi-hole later"
        else:
            up = {"ok": False}
            for base in (
                ["docker", "compose", "-f", str(ddir / "docker-compose.yml")],
                ["docker-compose", "-f", str(ddir / "docker-compose.yml")],
            ):
                up = _run([*base, "up", "-d"], timeout=180, cwd=str(ddir))
                if up.get("ok"):
                    break
            if not up.get("ok"):
                doh_note = (up.get("stderr") or up.get("stdout") or "docker compose up failed")[:300]
    out = {"ok": True, "safety_copy": str(safety), "restored": restored}
    if doh_note:
        out["doh_warning"] = doh_note
    return out


def realign_l2tp_secrets(data_dir: Path, active_secret_key: str) -> dict:
    """After restore, ciphertexts may be encrypted with a restored secret_key file while
    the running panel uses SECRET_KEY from the environment. Re-encrypt to the active key.
    """
    import base64
    import hashlib
    from cryptography.fernet import Fernet, InvalidToken

    def _fernet(sk: str) -> Fernet:
        return Fernet(base64.urlsafe_b64encode(hashlib.sha256(sk.encode()).digest()))

    active = (active_secret_key or "").strip()
    if not active:
        return {"ok": False, "error": "no active secret key", "reencrypted": 0}
    secrets_dir = Path(data_dir) / "l2tp_secrets"
    key_file = Path(data_dir) / "secret_key"
    candidates = [active]
    if key_file.is_file():
        try:
            fk = key_file.read_text(encoding="utf-8").strip()
            if fk and fk not in candidates:
                candidates.append(fk)
        except OSError:
            pass
    if not secrets_dir.is_dir():
        try:
            key_file.write_text(active, encoding="utf-8")
            os.chmod(key_file, 0o600)
        except OSError:
            pass
        return {"ok": True, "reencrypted": 0}
    active_f = _fernet(active)
    fernets = [_fernet(sk) for sk in candidates]
    n = 0
    bad = 0
    for path in sorted(secrets_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8") or "{}")
        except ValueError:
            bad += 1
            continue
        plain_pw = plain_psk = ""
        unlocked = False
        for f in fernets:
            try:
                plain_pw = f.decrypt(data["password"].encode()).decode() if data.get("password") else ""
                plain_psk = f.decrypt(data["psk"].encode()).decode() if data.get("psk") else ""
                unlocked = True
                break
            except (InvalidToken, ValueError, TypeError):
                continue
        if not unlocked:
            bad += 1
            continue
        new = {
            "password": active_f.encrypt(plain_pw.encode()).decode() if plain_pw else "",
            "psk": active_f.encrypt(plain_psk.encode()).decode() if plain_psk else "",
        }
        path.write_text(json.dumps(new), encoding="utf-8")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        n += 1
    try:
        key_file.write_text(active, encoding="utf-8")
        os.chmod(key_file, 0o600)
    except OSError:
        pass
    return {"ok": bad == 0, "reencrypted": n, "failed": bad}


def export_certs_bundle(*, max_file: int = PROMOTE_FILE_MAX) -> list[dict]:
    """List of {rel, data_b64} for promote / API transfer."""
    import base64
    out: list[dict] = []
    if not CERT_DIR.is_dir():
        return out
    for p in sorted(CERT_DIR.rglob("*")):
        if not p.is_file():
            continue
        try:
            if p.stat().st_size > max_file:
                continue
            rel = p.relative_to(CERT_DIR).as_posix()
            if not _safe_zip_name(rel):
                continue
            out.append({"rel": rel, "data_b64": base64.b64encode(p.read_bytes()).decode("ascii")})
        except OSError:
            continue
    return out


def import_certs_bundle(items: list | None) -> int:
    import base64
    n = 0
    for it in items or []:
        if not isinstance(it, dict):
            continue
        rel = str(it.get("rel") or "").replace("\\", "/")
        if not _safe_zip_name(rel):
            continue
        raw_b64 = it.get("data_b64") or ""
        try:
            raw = base64.b64decode(raw_b64)
        except Exception:
            continue
        target = CERT_DIR / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        try:
            if rel.endswith(".key"):
                os.chmod(target, 0o600)
        except OSError:
            pass
        n += 1
    return n


def export_doh_bundle(*, max_file: int = PROMOTE_FILE_MAX, max_total: int = 64 * 1024 * 1024) -> list[dict]:
    """DoH/Pi-hole files for promote (compose, .env, etc-pihole, dnsmasq). Skips oversized trees."""
    import base64
    root = doh_dir()
    out: list[dict] = []
    if not root.is_dir():
        return out
    total = 0
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        try:
            sz = p.stat().st_size
        except OSError:
            continue
        if sz > max_file:
            continue
        if total + sz > max_total:
            break
        rel = p.relative_to(root).as_posix()
        if not _safe_zip_name(rel):
            continue
        try:
            out.append({"rel": rel, "data_b64": base64.b64encode(p.read_bytes()).decode("ascii")})
            total += sz
        except OSError:
            continue
    return out


def import_doh_bundle(items: list | None, *, recreate: bool = True) -> dict:
    import base64
    root = doh_dir()
    n = 0
    for it in items or []:
        if not isinstance(it, dict):
            continue
        rel = str(it.get("rel") or "").replace("\\", "/")
        if not _safe_zip_name(rel):
            continue
        try:
            raw = base64.b64decode(it.get("data_b64") or "")
        except Exception:
            continue
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        try:
            if rel.endswith(".env") or rel.endswith(".key"):
                os.chmod(target, 0o600)
        except OSError:
            pass
        n += 1
    if recreate and n and (root / "docker-compose.yml").is_file():
        for base in (
            ["docker", "compose", "-f", str(root / "docker-compose.yml")],
            ["docker-compose", "-f", str(root / "docker-compose.yml")],
        ):
            up = _run([*base, "up", "-d", "--force-recreate"], timeout=180, cwd=str(root))
            if up.get("ok"):
                return {"ok": True, "files": n, "pihole": "recreated"}
        return {"ok": True, "files": n, "pihole": "files_only"}
    return {"ok": True, "files": n}


# ---------------------------------------------------------------- WARP / NordVPN

def warp_register(license_key: str = "") -> dict:
    """Register a Cloudflare WARP device; optionally attach a WARP+ license key.

    Flow: POST /reg → (optional) PUT /reg/{id}/account with ``{"license": "..."}``.
    Returns Xray wireguard outbound config + account meta (warp_plus / quota).
    """
    keys = _run([str(XRAY_BIN), "wg"])
    priv = pub = ""
    for line in keys["stdout"].splitlines():
        if "private" in line.lower():
            priv = line.split(":", 1)[1].strip()
        elif "public" in line.lower():
            pub = line.split(":", 1)[1].strip()
    if not priv:
        return {"ok": False, "error": "xray wg failed"}
    api = "https://api.cloudflareclient.com/v0a2158"
    hdr = {
        "Content-Type": "application/json",
        "CF-Client-Version": "a-6.30-3596",
        "User-Agent": "okhttp/3.12.1",
    }
    body = json.dumps({
        "key": pub, "install_id": "", "fcm_token": "",
        "tos": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
        "model": "PC", "serial_number": "", "locale": "en_US", "type": "Android",
        "warp_enabled": True,
    }).encode()
    try:
        resp = json.loads(_http(f"{api}/reg", 30, data=body, headers=hdr, method="POST"))
    except Exception as exc:
        return {"ok": False, "error": f"WARP API: {exc}"}
    device_id = str(resp.get("id") or "")
    token = str(resp.get("token") or "")
    account = resp.get("account") if isinstance(resp.get("account"), dict) else {}
    license_key = str(license_key or "").strip()
    warp_plus = bool(account.get("warp_plus"))
    premium = account.get("premium_data")
    quota = account.get("quota")
    account_type = str(account.get("account_type") or "")
    if license_key:
        if not device_id or not token:
            return {"ok": False, "error": "WARP: нет id/token после регистрации"}
        try:
            acc = json.loads(_http(
                f"{api}/reg/{device_id}/account", 30,
                data=json.dumps({"license": license_key}).encode(),
                headers={**hdr, "Authorization": f"Bearer {token}"},
                method="PUT",
            ))
            if isinstance(acc, dict):
                account = acc
                warp_plus = bool(acc.get("warp_plus"))
                premium = acc.get("premium_data", premium)
                quota = acc.get("quota", quota)
                account_type = str(acc.get("account_type") or account_type or "")
                if not warp_plus and str(acc.get("account_type") or "").lower() in ("unlimited", "team", "plus"):
                    warp_plus = True
        except Exception as exc:
            return {"ok": False, "error": f"WARP+ license: {exc}"}
        # PUT succeeded — treat as WARP+ even if flag lags in the response
        if not warp_plus:
            warp_plus = True

    cfg = resp.get("config") or {}
    peer = (cfg.get("peers") or [{}])[0]
    iface = (cfg.get("interface") or {}).get("addresses") or {}
    client_id = cfg.get("client_id") or ""
    reserved = []
    if client_id:
        import base64
        reserved = list(base64.b64decode(client_id))[:3]
    endpoint = (peer.get("endpoint") or {}).get("host") or "engage.cloudflareclient.com:2408"
    outbound = {
        "protocol": "wireguard",
        "settings": {
            "secretKey": priv,
            "address": [f"{iface.get('v4', '172.16.0.2')}/32", f"{iface.get('v6', '')}/128"] if iface.get("v6") else [f"{iface.get('v4', '172.16.0.2')}/32"],
            "peers": [{"publicKey": peer.get("public_key") or "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                       "endpoint": endpoint, "allowedIPs": ["0.0.0.0/0", "::/0"]}],
            "mtu": 1280,
            "noKernelTun": True,
            **({"reserved": reserved} if reserved else {}),
            "domainStrategy": "ForceIPv4v6",
        },
    }
    label = "Cloudflare WARP+" if (warp_plus or license_key) else "Cloudflare WARP"
    return {
        "ok": True,
        "config": outbound,
        "label": label,
        "warp_plus": bool(warp_plus or license_key),
        "account": {
            "id": device_id,
            "token": token,
            "warp_plus": bool(warp_plus or license_key),
            "account_type": account_type,
            "premium_data": premium,
            "quota": quota,
            "license_hint": (license_key[-4:] if len(license_key) >= 4 else ""),
        },
    }


def nord_servers(country_id: int | None = None, limit: int = 10) -> list[dict]:
    url = "https://api.nordvpn.com/v1/servers/recommendations?filters[servers_technologies][identifier]=wireguard_udp&limit=" + str(limit)
    if country_id:
        url += f"&filters[country_id]={country_id}"
    try:
        data = json.loads(_http(url, 30))
    except Exception:
        return []
    out = []
    for s in data:
        pk = ""
        for tech in s.get("technologies") or []:
            if tech.get("identifier") == "wireguard_udp":
                for m in tech.get("metadata") or []:
                    if m.get("name") == "public_key":
                        pk = m.get("value")
        loc = ((s.get("locations") or [{}])[0].get("country") or {})
        out.append({"hostname": s.get("hostname"), "station": s.get("station"), "load": s.get("load"),
                    "public_key": pk, "country": loc.get("name"), "code": loc.get("code")})
    return out


def nord_countries() -> list[dict]:
    try:
        data = json.loads(_http("https://api.nordvpn.com/v1/servers/countries", 30))
        return sorted([{"id": c["id"], "name": c["name"], "code": c["code"]} for c in data], key=lambda c: c["name"])
    except Exception:
        return []


def nord_private_key(token: str) -> dict:
    import base64
    auth = base64.b64encode(f"token:{token}".encode()).decode()
    try:
        data = json.loads(_http("https://api.nordvpn.com/v1/users/services/credentials", 30, headers={"Authorization": f"Basic {auth}"}))
        return {"ok": True, "private_key": data.get("nordlynx_private_key") or ""}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def nord_outbound(private_key: str, server: dict) -> dict:
    return {
        "protocol": "wireguard",
        "settings": {
            "secretKey": private_key,
            "address": ["10.5.0.2/32"],
            "peers": [{"publicKey": server["public_key"], "endpoint": f"{server['station']}:51820", "allowedIPs": ["0.0.0.0/0", "::/0"]}],
            "mtu": 1420,
            "noKernelTun": True,
            "domainStrategy": "ForceIPv4",
        },
    }


# ---------------------------------------------------------------- PIA (Private Internet Access)

def pia_countries() -> list[dict]:
    import pia as pia_mod

    res = pia_mod.list_regions()
    if not res.get("ok"):
        return []
    return pia_mod.countries_from_regions(res.get("regions") or [])


def pia_create_outbound(username: str, password: str, *, region_id: str = "", hostname: str = "",
                        token: str = "") -> dict:
    import pia as pia_mod

    return pia_mod.create_outbound(
        username, password, region_id=region_id, hostname=hostname, xray_bin=XRAY_BIN, token=token,
    )


def pia_provision(token: str, *, region_id: str = "", hostname: str = "") -> dict:
    import pia as pia_mod

    return pia_mod.provision_outbound(token, region_id=region_id, hostname=hostname, xray_bin=XRAY_BIN)


def pia_authenticate(username: str, password: str) -> dict:
    import pia as pia_mod

    return pia_mod.authenticate(username, password)


def speedtest(bytes_: int = 25_000_000) -> dict:
    r = _run(["curl", "-s", "-o", "/dev/null", "-w", "%{speed_download} %{time_total}", "--max-time", "60",
              f"https://speed.cloudflare.com/__down?bytes={bytes_}"], 70)
    parts = r["stdout"].split()
    if len(parts) < 2:
        return {"ok": False, "error": r["stderr"]}
    return {"ok": True, "mbps": round(float(parts[0]) * 8 / 1e6, 1), "seconds": float(parts[1])}


# ---------------------------------------------------------------- iperf3 (master ↔ node)

_IPERF_LOCK = threading.Lock()
_IPERF_SERVER_PROC: subprocess.Popen | None = None


def ensure_iperf3() -> dict:
    """Install iperf3 if missing (apt/yum). Idempotent."""
    which = _run(["bash", "-lc", "command -v iperf3"], 10)
    path = (which.get("stdout") or "").strip()
    if path:
        ver = _run([path, "-v"], 5)
        return {"ok": True, "path": path, "version": (ver.get("stdout") or ver.get("stderr") or "").splitlines()[:1]}
    install = _run(
        ["bash", "-lc",
         "export DEBIAN_FRONTEND=noninteractive; "
         "(command -v apt-get >/dev/null && apt-get install -y -qq iperf3) || "
         "(command -v dnf >/dev/null && dnf install -y -q iperf3) || "
         "(command -v yum >/dev/null && yum install -y -q iperf3) || exit 1"],
        180,
    )
    which2 = _run(["bash", "-lc", "command -v iperf3"], 10)
    path2 = (which2.get("stdout") or "").strip()
    if not path2:
        return {"ok": False, "error": install.get("stderr") or "iperf3 install failed"}
    return {"ok": True, "path": path2, "installed": True}


def _iperf3_bin() -> str:
    r = _run(["bash", "-lc", "command -v iperf3"], 5)
    return (r.get("stdout") or "").strip() or "iperf3"


def _iperf3_parse(raw: str) -> dict:
    """Extract mbps from iperf3 --json client output."""
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return {"ok": False, "error": "bad iperf3 json", "raw": (raw or "")[:400]}
    end = data.get("end") if isinstance(data, dict) else None
    if not isinstance(end, dict):
        err = ""
        if isinstance(data, dict):
            err = str((data.get("error") or ""))
        return {"ok": False, "error": err or "no end block"}
    sent = end.get("sum_sent") if isinstance(end.get("sum_sent"), dict) else {}
    recv = end.get("sum_received") if isinstance(end.get("sum_received"), dict) else {}
    # bidir nests under streams — also check sum
    if not sent and isinstance(end.get("sum"), dict):
        sent = end["sum"]
    def _mbps(block: dict) -> float | None:
        try:
            bps = float(block.get("bits_per_second") or 0)
        except (TypeError, ValueError):
            return None
        return round(bps / 1e6, 2)
    return {
        "ok": True,
        "send_mbps": _mbps(sent),
        "recv_mbps": _mbps(recv),
        "seconds": float((sent or recv).get("seconds") or 0) or None,
    }


def iperf3_firewall(port: int, *, open_: bool) -> None:
    """Best-effort temporary allow of TCP port (ufw / iptables / nft)."""
    port = int(port)
    if open_:
        _run(["bash", "-lc",
              f"command -v ufw >/dev/null && ufw allow {port}/tcp comment l2x-iperf3 || true; "
              f"iptables -C INPUT -p tcp --dport {port} -j ACCEPT 2>/dev/null || "
              f"iptables -I INPUT -p tcp --dport {port} -j ACCEPT 2>/dev/null || true"], 15)
    else:
        _run(["bash", "-lc",
              f"command -v ufw >/dev/null && ufw delete allow {port}/tcp >/dev/null 2>&1 || true; "
              f"iptables -D INPUT -p tcp --dport {port} -j ACCEPT 2>/dev/null || true"], 15)


def iperf3_server_stop() -> None:
    global _IPERF_SERVER_PROC
    with _IPERF_LOCK:
        proc = _IPERF_SERVER_PROC
        _IPERF_SERVER_PROC = None
    if proc and proc.poll() is None:
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
    _run(["bash", "-lc", "pkill -f 'iperf3 -s' 2>/dev/null || true"], 5)


def iperf3_server_start(port: int = 5201, *, one_off: bool = True) -> dict:
    """Start iperf3 server in background. one_off=True → exit after a single test."""
    ens = ensure_iperf3()
    if not ens.get("ok"):
        return ens
    bin_ = ens.get("path") or _iperf3_bin()
    iperf3_server_stop()
    port = max(1024, min(65535, int(port or 5201)))
    cmd = [bin_, "-s", "-p", str(port)]
    if one_off:
        cmd.append("-1")
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError as exc:
        return {"ok": False, "error": str(exc)}
    global _IPERF_SERVER_PROC
    with _IPERF_LOCK:
        _IPERF_SERVER_PROC = proc
    time.sleep(0.25)
    if proc.poll() is not None:
        return {"ok": False, "error": f"iperf3 server exited code {proc.returncode}"}
    iperf3_firewall(port, open_=True)
    return {"ok": True, "port": port, "pid": proc.pid, "one_off": one_off}


def iperf3_client(
    host: str,
    port: int = 5201,
    *,
    seconds: int = 8,
    reverse: bool = False,
    bidir: bool = False,
) -> dict:
    """Run iperf3 client; return send/recv mbps. reverse=True → server sends (master→node when master is server)."""
    ens = ensure_iperf3()
    if not ens.get("ok"):
        return ens
    host = (host or "").strip()
    if not host:
        return {"ok": False, "error": "host required"}
    port = max(1024, min(65535, int(port or 5201)))
    seconds = max(3, min(30, int(seconds or 8)))
    bin_ = ens.get("path") or _iperf3_bin()
    cmd = [bin_, "-c", host, "-p", str(port), "-t", str(seconds), "-J", "--connect-timeout", "5000"]
    if bidir:
        cmd.append("--bidir")
    elif reverse:
        cmd.append("-R")
    r = _run(cmd, seconds + 25)
    parsed = _iperf3_parse(r.get("stdout") or "")
    if not parsed.get("ok"):
        err = parsed.get("error") or r.get("stderr") or "iperf3 failed"
        if r.get("stderr") and err == "iperf3 failed":
            err = (r["stderr"] or "")[:300]
        return {"ok": False, "error": err, "code": r.get("code")}
    # When master is server and node is client:
    #  normal: send=node→master (↑ from node), recv=master→node is empty on client sum_received often equals download from server side
    #  -R:    server pushes → client's recv = master→node (↓ to node)
    out = {
        "ok": True,
        "host": host,
        "port": port,
        "seconds": seconds,
        "reverse": bool(reverse),
        "bidir": bool(bidir),
        "send_mbps": parsed.get("send_mbps"),
        "recv_mbps": parsed.get("recv_mbps"),
    }
    if reverse:
        out["down_mbps"] = parsed.get("recv_mbps")  # master → node
        out["up_mbps"] = parsed.get("send_mbps")
    else:
        out["up_mbps"] = parsed.get("send_mbps")    # node → master
        out["down_mbps"] = parsed.get("recv_mbps")
    return out


def iperf3_run_pair(host: str, port: int = 5201, *, seconds: int = 8) -> dict:
    """Two one-shot tests: ↑ node→master then ↓ master→node (caller must restart server between, or use persistent server)."""
    up = iperf3_client(host, port, seconds=seconds, reverse=False)
    if not up.get("ok"):
        return {"ok": False, "error": up.get("error") or "up failed", "up": up}
    down = iperf3_client(host, port, seconds=seconds, reverse=True)
    if not down.get("ok"):
        return {"ok": False, "error": down.get("error") or "down failed", "up": up, "down": down}
    return {
        "ok": True,
        "up_mbps": up.get("up_mbps"),
        "down_mbps": down.get("down_mbps"),
        "seconds": seconds,
        "host": host,
        "port": port,
        "up": up,
        "down": down,
    }
