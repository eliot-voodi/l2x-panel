"""Inbound parameter checks for the edit form: per-field issues + dry-run `xray run -test`.

Issue fields are form input names (inbound_edit.html) so the UI can highlight them.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import threading
from pathlib import Path

import front
import protocols as P
import xray_runtime as xray

ERROR = "error"
WARN = "warn"

REALITY_NETWORKS = ("raw", "grpc", "xhttp")
PATH_NETWORKS = {"ws": "ws_path", "httpupgrade": "hu_path", "xhttp": "xh_path"}
TLS_ORDER = {v: i for i, v in enumerate(P.TLS_VERSIONS)}


def _issue(out: list[dict], field: str, level: str, msg: str) -> None:
    out.append({"field": field, "level": level, "msg": msg})


def _host_of(dest: str) -> str:
    d = (dest or "").strip()
    if d.startswith("["):
        return d[1:].split("]", 1)[0]
    return d.rsplit(":", 1)[0] if ":" in d else d


def _plan_field(ib: dict, msg: str) -> str:
    low = msg.lower()
    sec = (ib.get("stream") or {}).get("security") or "none"
    if "sni" in low:
        return "r_names" if sec == "reality" else "tls_sni"
    if "путь" in low or "path" in low:
        net = (ib.get("stream") or {}).get("network") or "raw"
        return "grpc_service" if net == "grpc" else PATH_NETWORKS.get(net, "share_host")
    if "raw" in low:
        return "network"
    return "share_host"


def inbound_issues(store: dict, ib: dict) -> list[dict]:
    """Problems for one inbound model (already normalized by the form parser)."""
    out: list[dict] = []
    proto = ib.get("protocol") or "vless"
    st = ib.get("stream") or {}
    net = st.get("network") or "raw"
    sec = st.get("security") or "none"
    s = ib.get("settings") or {}
    direct = P.is_direct(ib)
    mode = P.front_mode(ib)
    pub = front.public_domain(store)
    others = [i for i in store.get("inbounds") or [] if i is not ib and i.get("id") != ib.get("id")]

    # --- identity / port
    if any(i.get("tag") == ib.get("tag") for i in others):
        _issue(out, "tag", ERROR, "Такой tag уже есть у другого inbound — Xray не запустится с дублями.")
    port = int(ib.get("port") or 0)
    if reason := xray.port_forbidden_reason(port):
        _issue(out, "port", ERROR, reason)
    elif any(int(i.get("port") or 0) == port for i in others):
        _issue(out, "port", ERROR, f"Порт {port} уже занят другим inbound — второй не сможет слушать.")

    # --- reachability
    if not direct and proto in P.FRONT_PROTOCOLS and mode is None:
        _issue(out, "direct", WARN,
               "Через nginx :443 этот вариант не публикуется (raw без TLS с header=http / vmess raw) — "
               "inbound доступен только локально. Включите «Напрямую на порт» или смените транспорт.")
    elif not direct and proto not in P.FRONT_PROTOCOLS and proto != "dokodemo-door":
        _issue(out, "direct", WARN,
               f"{proto} не проходит через nginx :443 — снаружи недоступен. Включите «Напрямую на порт».")
    if not direct and (net == "kcp" or proto == "hysteria"):
        _issue(out, "direct", ERROR, "UDP-транспорт (mKCP / Hysteria) не может идти через nginx :443 — нужен «Напрямую на порт».")

    # --- open proxies
    if proto in ("socks", "http") and s.get("auth") == "noauth" and direct:
        _issue(out, "auth", ERROR, "Прокси без пароля на 0.0.0.0 — открытый прокси для всего интернета. Включите логин/пароль.")
    if direct and proto in P.USER_PROTOCOLS and proto != "shadowsocks" and sec == "none" and proto != "hysteria":
        if not (proto == "vless" and P._vless_enc_on(s)):
            _issue(out, "security", WARN,
                   "Напрямую без TLS/Reality — трафик идёт открытым текстом и легко детектируется DPI.")

    # --- VLESS flow / encryption
    if proto == "vless":
        flow = s.get("flow") or ""
        if flow and not P.supports_flow(ib):
            _issue(out, "flow", ERROR,
                   f"xtls-rprx-vision работает только на raw + TLS/Reality (или с VLESS encryption). "
                   f"На {net}/{sec} flow будет отброшен — у клиентов со flow соединение не поднимется.")
        if flow and net == "raw" and sec == "tls":
            alpn = [a.strip() for a in (st.get("tls") or {}).get("alpn") or []]
            if "h2" in alpn and "http/1.1" not in alpn:
                _issue(out, "tls_alpn", WARN, "Vision поверх TLS: ALPN только h2 — оставьте http/1.1 (или h2,http/1.1).")
        if sec == "reality" and P._vless_enc_on(s):
            _issue(out, "vless_decryption", WARN, "С Reality VLESS encryption не нужна — оставьте decryption/encryption = none.")
        dec, enc = str(s.get("decryption") or "none"), str(s.get("encryption") or "none")
        if (dec == "none") != (enc == "none"):
            _issue(out, "vless_encryption", ERROR, "decryption и encryption должны быть заданы парой (или обе none).")
        if ib.get("fallbacks_enabled") is not False and P._vless_enc_on(s) and (ib.get("fallbacks") or mode == "raw"):
            _issue(out, "fallbacks_enabled", WARN,
                   "С VLESS encryption Xray не принимает fallbacks — они будут отключены автоматически.")

    # RAW front on :443: without fallbacks Xray drops all non-VLESS traffic for the public domain
    if mode == "raw" and not P.fallbacks_allowed(ib):
        _issue(out, "fallbacks_enabled", WARN,
               "Fallbacks выключены: сайт/панель на публичном домене через :443 перестанут открываться "
               "(Xray сбросит всё, что не VLESS). Панель останется доступна по прямому порту.")

    # --- Reality
    if sec == "reality":
        r = st.get("reality") or {}
        if net not in REALITY_NETWORKS:
            _issue(out, "network", ERROR, "Reality работает только с raw / grpc / xhttp.")
        dest = str(r.get("dest") or "").strip()
        if not dest:
            _issue(out, "r_dest", ERROR, "Нужен dest (сайт-маскировка), например www.cloudflare.com:443.")
        elif ":" not in dest.strip("[]") and not dest.isdigit():
            _issue(out, "r_dest", WARN, "dest без порта — обычно host:443.")
        names = [n for n in r.get("server_names") or [] if n]
        if not names:
            _issue(out, "r_names", ERROR, "Нужен хотя бы один Server name (SNI маскировки).")
        if pub and pub in names and not direct:
            _issue(out, "r_names", ERROR,
                   f"SNI «{pub}» = домен панели — nginx отдаст его панели, а не Xray. Укажите чужой домен (ya.ru, …).")
        dh = _host_of(dest)
        if dest and names and dh and not dh.replace(".", "").isdigit() and dh not in names:
            _issue(out, "r_names", WARN, f"Хост dest «{dh}» не входит в Server names — Reality-маскировка будет неправдоподобной.")
        if not r.get("private_key") or not r.get("public_key"):
            _issue(out, "r_priv", ERROR, "Нет пары ключей Reality — нажмите «Сгенерировать пару ключей».")
        for sid in r.get("short_ids") or []:
            sid_s = str(sid)
            if len(sid_s) > 16 or len(sid_s) % 2 or any(c not in "0123456789abcdefABCDEF" for c in sid_s):
                _issue(out, "r_sids", ERROR, f"Short ID «{sid_s}»: hex, чётная длина, до 16 символов.")
                break
        if ib.get("fallbacks") and P.fallbacks_allowed(ib):
            _issue(out, "fallbacks", WARN, "Fallbacks не работают с Reality (только raw + TLS).")

    # --- TLS
    if sec == "tls" or proto == "hysteria":
        tls = st.get("tls") or {}
        cert, key = str(tls.get("cert_file") or ""), str(tls.get("key_file") or "")
        if bool(cert) != bool(key):
            _issue(out, "tls_key" if cert else "tls_cert", ERROR, "Сертификат и ключ задаются парой.")
        if os.name != "nt":
            if cert and not Path(cert).is_file():
                _issue(out, "tls_cert", ERROR, f"Файл сертификата не найден: {cert}")
            if key and not Path(key).is_file():
                _issue(out, "tls_key", ERROR, f"Файл ключа не найден: {key}")
        if not cert and not direct and mode == "sni":
            _issue(out, "tls_cert", WARN, "TLS без сертификата: Xray не сможет завершить TLS — выберите выпущенный сертификат.")
        sni = str(tls.get("server_name") or "").strip()
        if not sni and not ib.get("share_host") and mode == "sni":
            _issue(out, "tls_sni", ERROR, "Для TLS через :443 нужен SNI (или URL share) — по нему nginx маршрутизирует.")
        lo, hi = TLS_ORDER.get(str(tls.get("min_version") or "1.2"), 2), TLS_ORDER.get(str(tls.get("max_version") or "1.3"), 3)
        if lo > hi:
            _issue(out, "tls_min", ERROR, "Min TLS больше Max TLS.")
        if tls.get("allow_insecure"):
            _issue(out, "tls_insecure", WARN, "allowInsecure в ссылках отключает проверку сертификата у клиентов.")

    # --- transports
    if proto in P.USER_PROTOCOLS and proto != "hysteria":
        if net in PATH_NETWORKS:
            field = PATH_NETWORKS[net]
            path = str(((st.get(net) or {}).get("path")) or "")
            if not path.startswith("/"):
                _issue(out, field, ERROR, "Path должен начинаться с «/».")
            elif mode == "http" and not front.PATH_RE.match(path.split("?", 1)[0]):
                _issue(out, field, ERROR, "Path через nginx: только латиница, цифры и /_.~-")
            elif mode == "http" and path.rstrip("/") in ("", "/sub", "/panel"):
                _issue(out, field, ERROR, "Этот путь занят панелью/подписками — выберите уникальный.")
        if net == "grpc":
            svc = str((st.get("grpc") or {}).get("service_name") or "")
            if not svc or "/" in svc.strip("/"):
                _issue(out, "grpc_service", ERROR, "serviceName: одно слово без «/».")
        if net == "raw" and (st.get("raw") or {}).get("header") == "http" and not direct:
            _issue(out, "raw_header", WARN, "raw с header=http не публикуется через nginx :443 — только «Напрямую».")
        if net == "xhttp":
            extra = str((st.get("xhttp") or {}).get("extra") or "").strip()
            if extra:
                try:
                    if not isinstance(json.loads(extra), dict):
                        raise ValueError
                except ValueError:
                    _issue(out, "xh_extra", ERROR, "Extra JSON: нужен JSON-объект {…}.")
        if ib.get("fallbacks") and P.fallbacks_allowed(ib) and not (net == "raw" and sec in ("tls", "none")):
            _issue(out, "fallbacks", WARN, "Fallbacks работают только с raw + TLS (или raw без security).")

    # --- routing
    so = st.get("sockopt") or {}
    dialer = str(so.get("dialer_proxy") or "").strip()
    known = set(xray.all_outbound_tags(store))
    if dialer and dialer not in known:
        _issue(out, "so_dialer", ERROR, f"Dialer proxy «{dialer}»: такого outbound нет.")
    ob = str(ib.get("outbound") or "").strip()
    if ob and ob not in ("none",) and ob not in known:
        _issue(out, "outbound", ERROR, f"Outbound «{ob}» не существует — правило уйдёт в direct.")
    if dialer and ob and dialer == ob:
        _issue(out, "so_dialer", ERROR, "Dialer proxy совпадает с outbound inbound — петля.")

    # --- nginx front plan (SNI clashes, duplicate paths, second RAW, …)
    if ib.get("enabled", True):
        plan_store = {"settings": store.get("settings") or {}, "inbounds": [*others, ib]}
        try:
            problems = front.plan(plan_store)["problems"]
        except Exception:
            problems = []
        tag = str(ib.get("tag") or "")
        share = str(ib.get("share_host") or "")
        for p in problems:
            if p.startswith(f"{tag}:") or (share and p.startswith(share)):
                _issue(out, _plan_field(ib, p), ERROR, p.split(":", 1)[1].strip() if p.startswith(f"{tag}:") else p)
    return out


def summarize(issues: list[dict]) -> dict:
    errs = [i for i in issues if i["level"] == ERROR]
    warns = [i for i in issues if i["level"] != ERROR]
    return {
        "errors": len(errs),
        "warnings": len(warns),
        "title": "\n".join(f"{'✖' if i['level'] == ERROR else '⚠'} {i['msg']}" for i in [*errs, *warns])[:1500],
    }


def map_xray_error_fields(ib: dict, error: str) -> list[dict]:
    """Turn a dry-test / apply Xray error into form-field highlights for the edit UI."""
    err = (error or "").strip()
    if not err:
        return []
    low = err.lower()
    out: list[dict] = []
    proto = ib.get("protocol") or ""
    st = ib.get("stream") or {}
    sec = st.get("security") or "none"

    if "fallback" in low and "decrypt" in low:
        msg = ("Xray: fallbacks нельзя вместе с decryption ≠ none. "
               "Снимите галочку Fallbacks или Authentication = None.")
        _issue(out, "fallbacks_enabled", ERROR, msg)
        _issue(out, "vless_auth", ERROR, msg)
        return out

    if "fallback" in low:
        _issue(out, "fallbacks", ERROR, f"Xray: {err}")
        return out

    if "reality" in low and ("private" in low or "public" in low or "key" in low):
        _issue(out, "r_priv", ERROR, f"Xray: {err}")
        return out

    if "shortid" in low or "short id" in low or "short_id" in low:
        _issue(out, "r_sids", ERROR, f"Xray: {err}")
        return out

    if "certificate" in low or "cert file" in low or ("tls" in low and ("fail" in low or "error" in low)):
        _issue(out, "tls_cert" if sec == "tls" or proto == "hysteria" else "security", ERROR, f"Xray: {err}")
        return out

    if "port" in low and ("already" in low or "bind" in low or "address already" in low):
        _issue(out, "port", ERROR, f"Xray: {err}")
        return out

    if "flow" in low or "vision" in low:
        _issue(out, "flow", ERROR, f"Xray: {err}")
        return out

    if "decrypt" in low or "encryption" in low:
        _issue(out, "vless_decryption", ERROR, f"Xray: {err}")
        return out

    # Unknown — still surface under tag so the form isn't "all green"
    _issue(out, "tag", ERROR, f"Xray: {err}")
    return out


_DRY_CACHE: dict[str, dict] = {}


def xray_dry_test(store: dict) -> dict:
    """Build the full config from ``store`` and run `xray run -test` on a private temp file.

    Results are cached by config hash — the inbounds page calls this on every load.
    """
    if not Path(xray.XRAY_BIN).is_file():
        return {"ok": None, "skipped": True, "error": f"xray не установлен ({xray.XRAY_BIN})"}
    try:
        cfg = xray.build_config(copy.deepcopy(store))
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"сборка конфига: {exc}"}
    body = json.dumps(cfg, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    key = hashlib.sha256(body.encode()).hexdigest()
    if key in _DRY_CACHE:
        return _DRY_CACHE[key]
    tmp = xray.XRAY_CONFIG.parent / f"{xray.XRAY_CONFIG.stem}.check.{os.getpid()}.{threading.get_ident()}.json"
    try:
        tmp.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(body, encoding="utf-8")
        res = xray._run([xray.XRAY_BIN, "run", "-test", "-config", str(tmp)], timeout=30)
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass
    ok = res["exit_code"] == 0
    out = {"ok": ok, "error": "" if ok else xray.clean_xray_error(res["stderr"] or res["stdout"])}
    if len(_DRY_CACHE) > 32:
        _DRY_CACHE.clear()
    _DRY_CACHE[key] = out
    return out
