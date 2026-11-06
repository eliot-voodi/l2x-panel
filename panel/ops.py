"""Host operations: Xray versions, geo files, logs, BBR, ACME certs, backups, WARP/NordVPN."""
from __future__ import annotations

import io
import ipaddress
import json
import os
import platform
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

    def runner():
        try:
            res = fn(*args)
            JOBS[job_id]["status"] = "done" if res.get("ok") else "failed"
            JOBS[job_id]["log"] = res.get("log") or res.get("error") or json.dumps(res, ensure_ascii=False)[:4000]
        except Exception as exc:  # noqa: BLE001
            JOBS[job_id]["status"] = "failed"
            JOBS[job_id]["log"] = str(exc)

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


PANEL_REPO = os.environ.get("L2X_REPO_API", "eliot-voodi/l2x-panel")


def panel_latest(include_prerelease: bool = False) -> dict:
    """Newest L2X Panel release on GitHub."""
    try:
        data = json.loads(_http(f"https://api.github.com/repos/{PANEL_REPO}/releases?per_page=15", 20))
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
        # fall back to main VERSION file
        try:
            raw = _http(f"https://raw.githubusercontent.com/{PANEL_REPO}/main/VERSION", 15).decode().strip()
            return {"ok": True, "tag": raw if raw.startswith("v") else f"v{raw}", "url": "", "published": "",
                    "prerelease": False, "notes": ""}
        except Exception as exc:
            return {"ok": False, "error": f"нет релизов: {exc}"}
    return {
        "ok": True,
        "tag": best["tag_name"],
        "url": best.get("html_url") or "",
        "published": best.get("published_at") or "",
        "prerelease": bool(best.get("prerelease")),
        "notes": (best.get("body") or "")[:4000],
    }


def update_panel() -> dict:
    """Run install.sh --update (keeps data). Panel process will restart."""
    script = (
        "curl -fsSL https://raw.githubusercontent.com/eliot-voodi/l2x-panel/main/install.sh "
        "| bash -s -- --update"
    )
    if Path("/usr/local/bin/l2x").exists():
        r = _run(["/usr/local/bin/l2x", "update"], timeout=900)
    else:
        r = _run(["bash", "-lc", script], timeout=900)
    log = (r.get("stdout") or "")[-3000:] + ("\n" + (r.get("stderr") or "")[-1000:] if r.get("stderr") else "")
    ver = ""
    try:
        ver = Path("/opt/l2xpanel/VERSION").read_text(encoding="utf-8").strip().splitlines()[0]
    except OSError:
        pass
    return {"ok": bool(r.get("ok")), "log": log or f"exit {r.get('code')}", "version": ver,
            "error": "" if r.get("ok") else (r.get("stderr") or "update failed")}


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


def install_xray(version: str) -> dict:
    version = version if version.startswith("v") else f"v{version}"
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
    backup = XRAY_BIN.with_suffix(".bak")
    had_old = XRAY_BIN.exists()
    if had_old:
        shutil.copy2(XRAY_BIN, backup)
    os.replace(tmp, XRAY_BIN)
    # The current config must still pass with the new core, otherwise roll back
    cfg = os.environ.get("XRAY_CONFIG", "/etc/xray/config.json")
    log = [f"downloaded {version}", test["stdout"].splitlines()[0] if test["stdout"] else ""]
    if Path(cfg).exists():
        check = _run([str(XRAY_BIN), "run", "-test", "-config", cfg], 60)
        if not check["ok"]:
            if had_old:
                os.replace(backup, XRAY_BIN)
            return {"ok": False, "error": "текущий конфиг не проходит xray -test на новой версии, откат:\n"
                                          + (check["stderr"] or check["stdout"])[-1500:]}
        log.append("config test: ok")
    r = _run(["systemctl", "restart", "xray"], 30)
    time.sleep(3)
    active = _run(["systemctl", "is-active", "xray"])["stdout"].strip() == "active"
    if not (r["ok"] and active):
        if had_old:
            os.replace(backup, XRAY_BIN)
            _run(["systemctl", "restart", "xray"], 30)
        return {"ok": False, "error": f"Xray {version} не запустился, возвращена прежняя версия\n{r['stderr'][-800:]}"}
    log.append(f"installed {version}, xray active")
    return {"ok": True, "log": "\n".join(x for x in log if x), "version": version}


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
    GEO_DIR.mkdir(parents=True, exist_ok=True)
    log = []
    sources = dict(GEO_SOURCES)
    for item in custom or []:
        name = str(item.get("name") or "").strip()
        if name and item.get("url"):
            sources[name if name.endswith(".dat") else f"{name}.dat"] = item["url"]
    ok = True
    for name, url in sources.items():
        try:
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


def tail(path: str, lines: int = 300) -> str:
    p = Path(path)
    if not p.exists():
        return f"{path}: нет файла (включите access log в настройках Xray)"
    r = _run(["tail", "-n", str(lines), str(p)], 10)
    return r["stdout"]


# ---------------------------------------------------------------- BBR

def bbr_status() -> dict:
    cc = _run(["sysctl", "-n", "net.ipv4.tcp_congestion_control"])["stdout"].strip()
    qd = _run(["sysctl", "-n", "net.core.default_qdisc"])["stdout"].strip()
    return {"enabled": cc == "bbr", "congestion": cc, "qdisc": qd}


def bbr_set(enable: bool) -> dict:
    conf = Path("/etc/sysctl.d/99-l2x-bbr.conf")
    if enable:
        conf.write_text("net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n")
    else:
        conf.write_text("net.core.default_qdisc=fq_codel\nnet.ipv4.tcp_congestion_control=cubic\n")
    r = _run(["sysctl", "-p", str(conf)])
    return {"ok": r["ok"], **bbr_status(), "error": r["stderr"]}


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
                              "systemd-run --on-active=5 systemctl restart l2xpanel"],
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


def make_backup(data_dir: Path) -> bytes:
    """Full system backup: panel data + TLS certs + DoH/Pi-hole compose volumes."""
    buf = io.BytesIO()
    counts = {"data": 0, "certs": 0, "doh": 0}
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(data_dir.rglob("*")):
            if not p.is_file():
                continue
            if p.name in BACKUP_EXCLUDE or p.name.startswith("pre-restore-"):
                continue
            rel = p.relative_to(data_dir).as_posix()
            if not _safe_zip_name(rel):
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

def warp_register() -> dict:
    """Register a Cloudflare WARP device; returns Xray wireguard outbound config."""
    keys = _run([str(XRAY_BIN), "wg"])
    priv = pub = ""
    for line in keys["stdout"].splitlines():
        if "private" in line.lower():
            priv = line.split(":", 1)[1].strip()
        elif "public" in line.lower():
            pub = line.split(":", 1)[1].strip()
    if not priv:
        return {"ok": False, "error": "xray wg failed"}
    body = json.dumps({
        "key": pub, "install_id": "", "fcm_token": "", "tos": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
        "model": "PC", "serial_number": "", "locale": "en_US",
    }).encode()
    try:
        resp = json.loads(_http("https://api.cloudflareclient.com/v0a2158/reg", 30, data=body,
                                headers={"Content-Type": "application/json", "CF-Client-Version": "a-6.30-3596"}, method="POST"))
    except Exception as exc:
        return {"ok": False, "error": f"WARP API: {exc}"}
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
    return {"ok": True, "config": outbound, "account": {"id": resp.get("id"), "token": resp.get("token")}}


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
