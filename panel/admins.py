"""Panel administrator accounts (multiple local admins, shared global 2FA)."""
from __future__ import annotations

from collections.abc import Callable
import json
import os
import secrets
import time
from pathlib import Path

import bcrypt

_LEGACY = "admin.json"
_STORE = "admins.json"


def data_dir() -> Path:
    raw = os.environ.get("L2XPANEL_DATA", "").strip()
    if raw:
        return Path(raw)
    return Path(__file__).resolve().parent / "data"


def _legacy_path() -> Path:
    return data_dir() / _LEGACY


def _store_path() -> Path:
    return data_dir() / _STORE


def _new_id() -> str:
    return secrets.token_urlsafe(9).replace("-", "").replace("_", "")[:16]


def _write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False), encoding="utf-8")
    os.chmod(path, 0o600)


def _load_store() -> list[dict]:
    p = _store_path()
    if p.exists():
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
        except ValueError:
            raw = {}
        if isinstance(raw.get("admins"), list) and raw["admins"]:
            return [dict(x) for x in raw["admins"]]
    return []


def _migrate_legacy() -> list[dict] | None:
    lp = _legacy_path()
    if not lp.exists():
        return None
    try:
        leg = json.loads(lp.read_text(encoding="utf-8"))
    except ValueError:
        return None
    if isinstance(leg.get("admins"), list):
        return None
    uname = str(leg.get("username") or "").strip()
    ph = str(leg.get("password_hash") or "").strip()
    if not uname or not ph:
        return None
    return [{"id": _new_id(), "username": uname, "password_hash": ph, "created": int(time.time())}]


def _save_admins(admins: list[dict]) -> None:
    _write_json(_store_path(), {"version": 1, "admins": admins})
    _sync_legacy_mirror(admins)


def _sync_legacy_mirror(admins: list[dict]) -> None:
    if not admins:
        return
    primary = admins[0]
    _write_json(
        _legacy_path(),
        {"username": primary["username"], "password_hash": primary["password_hash"]},
    )


def ensure(
    *,
    default_user: str = "admin",
    default_password_env: str = "",
    on_new_password: Callable[[str, str], None] | None = None,
) -> list[dict]:
    """Load or bootstrap admin list (call at startup)."""
    admins = _load_store()
    if not admins:
        migrated = _migrate_legacy()
        if migrated:
            admins = migrated
            _save_admins(admins)
            return admins
        legacy = data_dir() / "admin.bcrypt"
        password: str | None = None
        if legacy.exists():
            pw_hash = legacy.read_bytes().decode()
        else:
            password = default_password_env or secrets.token_urlsafe(16)
            pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        admins = [
            {
                "id": _new_id(),
                "username": default_user,
                "password_hash": pw_hash,
                "created": int(time.time()),
            }
        ]
        _save_admins(admins)
        if password is not None and not default_password_env and on_new_password:
            on_new_password(default_user, password)
    else:
        _sync_legacy_mirror(admins)
    return admins


def list_admins() -> list[dict]:
    ensure()
    return _load_store()


def primary() -> dict:
    admins = list_admins()
    return admins[0] if admins else {"username": "admin", "password_hash": ""}


def get_by_username(username: str) -> dict | None:
    u = (username or "").strip()
    if not u:
        return None
    for a in list_admins():
        if secrets.compare_digest(a.get("username") or "", u):
            return a
    return None


def get_by_id(admin_id: str) -> dict | None:
    aid = (admin_id or "").strip()
    for a in list_admins():
        if a.get("id") == aid:
            return a
    return None


def public_rows() -> list[dict]:
    """Rows safe for UI (no password hashes)."""
    return [
        {
            "id": a.get("id") or "",
            "username": a.get("username") or "",
            "created": int(a.get("created") or 0),
        }
        for a in list_admins()
    ]


def check_credentials(username: str, password: str) -> bool:
    for a in list_admins():
        if not secrets.compare_digest(username, a.get("username") or ""):
            continue
        try:
            if bcrypt.checkpw(password.encode(), (a.get("password_hash") or "").encode()):
                return True
        except ValueError:
            pass
    return False


def username_taken(username: str, *, except_id: str | None = None) -> bool:
    u = username.strip()
    for a in list_admins():
        if except_id and a.get("id") == except_id:
            continue
        if secrets.compare_digest(a.get("username") or "", u):
            return True
    return False


def add_admin(username: str, password: str) -> tuple[bool, str]:
    username = username.strip()
    if not username or len(username) > 64:
        return False, "Некорректный логин"
    if len(password) < 8:
        return False, "Пароль минимум 8 символов"
    if username_taken(username):
        return False, "Такой логин уже есть"
    admins = list_admins()
    admins.append(
        {
            "id": _new_id(),
            "username": username,
            "password_hash": bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode(),
            "created": int(time.time()),
        }
    )
    _save_admins(admins)
    return True, ""


def update_account(
    admin_id: str,
    *,
    username: str | None = None,
    new_password: str | None = None,
) -> tuple[bool, str, dict | None]:
    admins = list_admins()
    idx = next((i for i, a in enumerate(admins) if a.get("id") == admin_id), None)
    if idx is None:
        return False, "Администратор не найден", None
    rec = admins[idx]
    if username is not None:
        username = username.strip()
        if not username:
            return False, "Некорректный логин", None
        if username_taken(username, except_id=admin_id):
            return False, "Такой логин уже есть", None
        rec["username"] = username
    if new_password:
        if len(new_password) < 8:
            return False, "Пароль минимум 8 символов", None
        rec["password_hash"] = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
    admins[idx] = rec
    _save_admins(admins)
    return True, "", rec


def delete_admin(admin_id: str) -> tuple[bool, str]:
    admins = list_admins()
    if len(admins) <= 1:
        return False, "Нельзя удалить последнего администратора"
    nxt = [a for a in admins if a.get("id") != admin_id]
    if len(nxt) == len(admins):
        return False, "Администратор не найден"
    _save_admins(nxt)
    return True, ""


def set_primary_password(password: str) -> tuple[bool, str]:
    if len(password) < 8:
        return False, "пароль минимум 8 символов"
    admins = list_admins()
    if not admins:
        return False, "нет администраторов"
    admins[0]["password_hash"] = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    _save_admins(admins)
    return True, ""
