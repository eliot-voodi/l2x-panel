"""Yandex Cloud Compute watchdog — keep a VM running (default: Kazakhstan region)."""
from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

REGIONS: dict[str, dict[str, str]] = {
    "kz": {
        "label": "Казахстан (Yandex Cloud KZ)",
        "iam": "https://iam.api.yandexcloud.kz",
        "compute": "https://compute.api.yandexcloud.kz",
        "console": "https://kz.console.yandex.cloud",
        "aud": "https://iam.api.yandexcloud.kz/iam/v1/tokens",
    },
    "ru": {
        "label": "Россия (Yandex Cloud)",
        "iam": "https://iam.api.cloud.yandex.net",
        "compute": "https://compute.api.cloud.yandex.net",
        "console": "https://console.yandex.cloud",
        "aud": "https://iam.api.cloud.yandex.net/iam/v1/tokens",
    },
}

# Treat these as "off" → auto-start
STOPPED_STATUSES = frozenset({"STOPPED", "CRASHED", "ERROR"})
# Do not spam start while transitioning
BUSY_STATUSES = frozenset({"PROVISIONING", "STARTING", "RESTARTING", "UPDATING", "STOPPING", "DELETING"})


def default_settings() -> dict[str, Any]:
    return {
        "enabled": False,
        "region": "kz",
        "folder_id": "",
        "instance_id": "",
        "instance_name": "",
        "auth_mode": "sa_key",  # sa_key (рекомендуется для KZ) | oauth
        "oauth_token": "",
        "sa_key_json": "",
        "check_interval_sec": 60,
        "auto_start": True,
        "iam_token": "",
        "iam_expires_at": "",
        "last_check_at": "",
        "last_status": "",
        "last_name": "",
        "last_error": "",
        "last_action": "",
        "last_action_at": "",
        "last_http": 0,
    }


def ensure_settings(store: dict) -> dict:
    s = store.setdefault("settings", {})
    yc = s.setdefault("yacloud", {})
    if not isinstance(yc, dict):
        yc = {}
        s["yacloud"] = yc
    base = default_settings()
    for k, v in base.items():
        yc.setdefault(k, v)
    yc["enabled"] = bool(yc.get("enabled"))
    yc["auto_start"] = bool(yc.get("auto_start", True))
    region = str(yc.get("region") or "kz").strip().lower()
    yc["region"] = region if region in REGIONS else "kz"
    mode = str(yc.get("auth_mode") or "oauth").strip().lower()
    yc["auth_mode"] = mode if mode in ("oauth", "sa_key") else "oauth"
    try:
        iv = int(yc.get("check_interval_sec") or 60)
    except Exception:
        iv = 60
    yc["check_interval_sec"] = max(30, min(3600, iv))
    return yc


def region_meta(region: str | None = None) -> dict[str, str]:
    key = str(region or "kz").strip().lower()
    return REGIONS.get(key) or REGIONS["kz"]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _http_json(
    method: str,
    url: str,
    *,
    token: str = "",
    body: dict | None = None,
    timeout: float = 25.0,
) -> tuple[int, dict | list | str]:
    data = None
    headers = {"Accept": "application/json", "User-Agent": "l2xpanel-yacloud/1.0"}
    if body is not None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method.upper())
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
            code = int(resp.status)
            if not raw.strip():
                return code, {}
            try:
                return code, json.loads(raw)
            except Exception:
                return code, raw
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace") if exc.fp else ""
        try:
            payload = json.loads(raw) if raw else {"message": str(exc)}
        except Exception:
            payload = {"message": raw or str(exc)}
        return int(exc.code), payload if isinstance(payload, dict) else {"message": str(payload)}
    except Exception as exc:  # noqa: BLE001
        return 0, {"message": str(exc)}


def _parse_sa_key(raw: str) -> dict[str, str]:
    """Accept yc key.json or IAM Key.create response shapes."""
    text = (raw or "").strip()
    if not text:
        raise ValueError("Пустой JSON ключа сервисного аккаунта")
    obj = json.loads(text)
    if not isinstance(obj, dict):
        raise ValueError("Ключ должен быть JSON-объектом")
    # Nested { "key": {...}, "privateKey": "..." }
    if isinstance(obj.get("key"), dict) and (obj.get("privateKey") or obj.get("private_key")):
        key = obj["key"]
        return {
            "id": str(key.get("id") or "").strip(),
            "service_account_id": str(key.get("serviceAccountId") or key.get("service_account_id") or "").strip(),
            "private_key": str(obj.get("privateKey") or obj.get("private_key") or ""),
        }
    return {
        "id": str(obj.get("id") or obj.get("key_id") or "").strip(),
        "service_account_id": str(
            obj.get("service_account_id") or obj.get("serviceAccountId") or obj.get("iss") or ""
        ).strip(),
        "private_key": str(obj.get("private_key") or obj.get("privateKey") or ""),
    }


def _jwt_for_sa(sa_key: dict[str, str], aud: str) -> str:
    kid = sa_key.get("id") or ""
    iss = sa_key.get("service_account_id") or ""
    pem = sa_key.get("private_key") or ""
    if not kid or not iss or not pem:
        raise ValueError("В ключе нужны id, service_account_id и private_key")
    if "\\n" in pem and "\n" not in pem:
        pem = pem.replace("\\n", "\n")
    header = {"typ": "JWT", "alg": "PS256", "kid": kid}
    now = int(time.time())
    payload = {"iss": iss, "aud": aud, "iat": now, "exp": now + 3600}
    h = _b64url(json.dumps(header, separators=(",", ":"), ensure_ascii=False).encode())
    p = _b64url(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode())
    signing = f"{h}.{p}".encode("ascii")
    key = serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
    sig = key.sign(
        signing,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
        hashes.SHA256(),
    )
    return f"{h}.{p}.{_b64url(sig)}"


def _iam_still_valid(yc: dict, *, skew_sec: int = 120) -> bool:
    token = str(yc.get("iam_token") or "").strip()
    exp = str(yc.get("iam_expires_at") or "").strip()
    if not token or not exp:
        return False
    try:
        # RFC3339
        if exp.endswith("Z"):
            exp_dt = datetime.fromisoformat(exp.replace("Z", "+00:00"))
        else:
            exp_dt = datetime.fromisoformat(exp)
        if exp_dt.tzinfo is None:
            exp_dt = exp_dt.replace(tzinfo=timezone.utc)
        return exp_dt.timestamp() > time.time() + skew_sec
    except Exception:
        return False


def _format_iam_error(code: int, payload: dict | list | str, *, region: str, mode: str) -> str:
    msg = ""
    if isinstance(payload, dict):
        msg = str(payload.get("message") or payload.get("error") or "")
    elif payload:
        msg = str(payload)
    low = msg.lower()
    # Typical KZ OAuth failure: Yandex passport OK, but account has no KZ cloud
    if code == 401 and (
        "not registered" in low
        or "does not registered" in low
        or "не зарегистрирован" in low
    ):
        console = region_meta(region).get("console") or "https://kz.console.yandex.cloud"
        return (
            f"IAM 401: аккаунт не зарегистрирован в Yandex Cloud ({region}). "
            f"Зайдите в {console}, создайте облако/платёжный аккаунт, "
            f"либо используйте ключ сервисного аккаунта из этой же консоли (режим SA key)."
        )[:420]
    if code == 401:
        hint = " Проверьте OAuth/ключ и регион (KZ ≠ RU)." if mode == "oauth" else " Проверьте SA key и регион."
        return (f"IAM token: HTTP {code} {msg}.{hint}")[:420]
    return (f"IAM token: HTTP {code} {msg}")[:420]


def obtain_iam_token(yc: dict) -> str:
    """Return a valid IAM token, refreshing via OAuth or SA key when needed."""
    if _iam_still_valid(yc):
        return str(yc.get("iam_token") or "")
    meta = region_meta(yc.get("region"))
    url = f"{meta['iam']}/iam/v1/tokens"
    mode = str(yc.get("auth_mode") or "oauth")
    body: dict[str, Any]
    if mode == "sa_key":
        sa = _parse_sa_key(str(yc.get("sa_key_json") or ""))
        jwt = _jwt_for_sa(sa, meta["aud"])
        body = {"jwt": jwt}
    else:
        oauth = str(yc.get("oauth_token") or "").strip()
        if not oauth:
            raise ValueError("Не задан OAuth-токен Яндекса")
        body = {"yandexPassportOauthToken": oauth}
    code, payload = _http_json("POST", url, body=body)
    if code != 200 or not isinstance(payload, dict) or not payload.get("iamToken"):
        # Drop stale cache so next tick retries exchange
        yc["iam_token"] = ""
        yc["iam_expires_at"] = ""
        raise ValueError(
            _format_iam_error(code, payload, region=str(yc.get("region") or "kz"), mode=mode)
        )
    yc["iam_token"] = str(payload["iamToken"])
    yc["iam_expires_at"] = str(payload.get("expiresAt") or "")
    return yc["iam_token"]


def resolve_instance_id(yc: dict, token: str) -> str:
    iid = str(yc.get("instance_id") or "").strip()
    if iid:
        return iid
    name = str(yc.get("instance_name") or "").strip()
    folder = str(yc.get("folder_id") or "").strip()
    if not name or not folder:
        raise ValueError("Укажите instance_id или пару folder_id + имя ВМ")
    meta = region_meta(yc.get("region"))
    q = urllib.parse.urlencode({"folderId": folder, "filter": f'name="{name}"', "pageSize": "100"})
    url = f"{meta['compute']}/compute/v1/instances?{q}"
    code, payload = _http_json("GET", url, token=token)
    if code != 200 or not isinstance(payload, dict):
        raise ValueError(f"List instances: HTTP {code}")
    items = payload.get("instances") or []
    if not isinstance(items, list) or not items:
        raise ValueError(f"ВМ с именем «{name}» не найдена в folder {folder}")
    found = next((i for i in items if isinstance(i, dict) and str(i.get("name") or "") == name), items[0])
    iid = str((found or {}).get("id") or "").strip()
    if not iid:
        raise ValueError("В ответе List нет id инстанса")
    yc["instance_id"] = iid
    return iid


def get_instance(yc: dict, token: str, instance_id: str) -> dict:
    meta = region_meta(yc.get("region"))
    url = f"{meta['compute']}/compute/v1/instances/{urllib.parse.quote(instance_id)}"
    code, payload = _http_json("GET", url, token=token)
    yc["last_http"] = code
    if code != 200 or not isinstance(payload, dict):
        msg = ""
        if isinstance(payload, dict):
            msg = str(payload.get("message") or payload)
        raise ValueError(f"Get instance: HTTP {code} {msg}"[:300])
    return payload


def start_instance(yc: dict, token: str, instance_id: str) -> dict:
    meta = region_meta(yc.get("region"))
    url = f"{meta['compute']}/compute/v1/instances/{urllib.parse.quote(instance_id)}:start"
    code, payload = _http_json("POST", url, token=token, body={})
    yc["last_http"] = code
    if code not in (200, 201) or not isinstance(payload, (dict,)):
        msg = ""
        if isinstance(payload, dict):
            msg = str(payload.get("message") or payload)
        raise ValueError(f"Start instance: HTTP {code} {msg}"[:300])
    return payload if isinstance(payload, dict) else {}


def public_view(yc: dict) -> dict:
    """Safe dict for UI (secrets masked)."""
    out = dict(yc or {})
    for key in ("oauth_token", "sa_key_json", "iam_token"):
        val = str(out.get(key) or "")
        out[f"{key}_set"] = bool(val.strip())
        out[key] = ""
    out["region_label"] = region_meta(out.get("region")).get("label") or ""
    out["console"] = region_meta(out.get("region")).get("console") or ""
    return out


def check_and_start(store: dict, *, force_start: bool = False) -> dict:
    """One watchdog tick. Mutates store settings.yacloud. Returns status dict."""
    yc = ensure_settings(store)
    result = {
        "ok": False,
        "status": "",
        "action": "",
        "error": "",
        "instance_id": str(yc.get("instance_id") or ""),
        "name": str(yc.get("last_name") or yc.get("instance_name") or ""),
    }
    if not yc.get("enabled") and not force_start:
        result["error"] = "watchdog выключен"
        return result
    try:
        token = obtain_iam_token(yc)
        iid = resolve_instance_id(yc, token)
        result["instance_id"] = iid
        inst = get_instance(yc, token, iid)
        status = str(inst.get("status") or "").upper()
        name = str(inst.get("name") or "")
        folder = str(inst.get("folderId") or inst.get("folder_id") or "").strip()
        result["status"] = status
        result["name"] = name
        yc["last_check_at"] = _now_iso()
        yc["last_status"] = status
        yc["last_name"] = name
        yc["last_error"] = ""
        # Auto-fill folder / name from live instance (no manual console hunting)
        if folder:
            yc["folder_id"] = folder
        if name and not str(yc.get("instance_name") or "").strip():
            yc["instance_name"] = name
        if name:
            result["name"] = name

        need_start = force_start or (
            bool(yc.get("auto_start", True)) and status in STOPPED_STATUSES
        )
        if status in BUSY_STATUSES and not force_start:
            result["action"] = f"wait:{status.lower()}"
            yc["last_action"] = result["action"]
            yc["last_action_at"] = _now_iso()
            result["ok"] = True
            return result
        if need_start:
            start_instance(yc, token, iid)
            result["action"] = "started"
            yc["last_action"] = "started"
            yc["last_action_at"] = _now_iso()
        else:
            result["action"] = "ok" if status == "RUNNING" else f"noop:{status.lower() or 'unknown'}"
            yc["last_action"] = result["action"]
            yc["last_action_at"] = _now_iso()
        result["ok"] = True
        return result
    except Exception as exc:  # noqa: BLE001
        err = str(exc)[:400]
        result["error"] = err
        yc["last_check_at"] = _now_iso()
        yc["last_error"] = err
        yc["last_action"] = "error"
        yc["last_action_at"] = _now_iso()
        return result
