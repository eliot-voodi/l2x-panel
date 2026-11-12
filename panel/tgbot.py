"""Telegram bot: admin notifications, reports, backups and lookup commands (long polling)."""
from __future__ import annotations

import contextvars
import html
import json
import logging
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Callable

API = "https://api.telegram.org/bot{token}/{method}"
# Local SOCKS injected into Xray when Telegram proxy type = outbound (VLESS/etc.).
TG_LOCAL_SOCKS_TAG = "l2x-tg-proxy"
TG_LOCAL_SOCKS_PORT = 10929
log = logging.getLogger("l2x.tgbot")

# Who triggered a panel change (login + IP). Copied into background jobs via ops.start_job.
_actor_line: contextvars.ContextVar[str] = contextvars.ContextVar("l2x_tg_actor", default="")
_actor_user: contextvars.ContextVar[str] = contextvars.ContextVar("l2x_tg_actor_user", default="")
_actor_ip: contextvars.ContextVar[str] = contextvars.ContextVar("l2x_tg_actor_ip", default="")


def bind_actor(username: str, ip: str) -> None:
    """Remember panel operator for subsequent admin notifications in this request/job."""
    raw_user = str(username or "?").strip() or "?"
    raw_ip = str(ip or "?").strip() or "?"
    _actor_user.set(raw_user)
    _actor_ip.set(raw_ip)
    _actor_line.set(f"\n👤 <b>{escape(raw_user)}</b> · <code>{escape(raw_ip)}</code>")


def clear_actor() -> None:
    _actor_line.set("")
    _actor_user.set("")
    _actor_ip.set("")


def get_actor() -> str:
    return _actor_line.get() or ""


def get_actor_meta() -> dict:
    return {"user": _actor_user.get() or "", "ip": _actor_ip.get() or ""}


def set_actor(line: str):
    """Set raw actor suffix (used when hopping into a worker thread)."""
    return _actor_line.set(line or "")


def reset_actor(token) -> None:
    _actor_line.reset(token)


def default_settings() -> dict:
    return {
        "enabled": False,
        "token": "",
        "admin_ids": [],
        # Long-poll commands on this node (disable on standby if the same bot token is shared)
        "receive_commands": True,
        "notify_login": True,
        "notify_quota": True,
        "notify_expire_days": 3,
        "notify_iplimit": True,
        "notify_nodes": True,      # online/offline, sync, update, provision, promote, changes
        "notify_changes": True,    # clients, inbounds, outbounds, DoH, settings
        "notify_updates": True,    # new Xray core / panel releases on GitHub
        "cpu_threshold": 85,
        "report_hours": 24,
        "backup_hours": 24,
        # unix ts of last successful scheduled TG backup (persisted in store)
        "last_backup_at": 0,
        # All Bot API traffic (notify + long-poll) via proxy.
        # type: http | socks5 | socks4 | outbound
        # outbound = route through an existing panel outbound (VLESS/Trojan/…) via local Xray SOCKS.
        # MTProto is for Telegram clients only — Bot API is HTTPS and cannot speak MTProxy.
        "proxy": {
            "enabled": False,
            "type": "socks5",
            "url": "",
            "host": "",
            "port": 1080,
            "user": "",
            "password": "",
            "outbound": "",
        },
    }


def parse_proxy_url(url: str) -> dict:
    """Parse http://user:pass@host:port or socks5://… into proxy fields."""
    raw = str(url or "").strip()
    if not raw:
        return {}
    if "://" not in raw:
        raw = "socks5://" + raw
    u = urllib.parse.urlparse(raw)
    scheme = (u.scheme or "socks5").lower()
    if scheme in ("socks", "socks5h"):
        scheme = "socks5"
    elif scheme == "socks4a":
        scheme = "socks4"
    elif scheme in ("https",):
        scheme = "http"
    host = u.hostname or ""
    port = int(u.port or (443 if scheme == "http" and raw.lower().startswith("https") else 1080))
    if scheme == "http" and not u.port:
        port = 8080
    return {
        "type": scheme if scheme in ("http", "socks5", "socks4") else "socks5",
        "host": host,
        "port": port,
        "user": urllib.parse.unquote(u.username or ""),
        "password": urllib.parse.unquote(u.password or ""),
    }


def proxy_endpoint(settings: dict) -> dict | None:
    """Resolved proxy for urllib: {type, host, port, user, password} or None."""
    proxy = (settings or {}).get("proxy") or {}
    if not proxy.get("enabled"):
        return None
    ptype = str(proxy.get("type") or "socks5").lower().strip()
    if ptype in ("mtproto", "mtproxy", "tg"):
        # Not usable for Bot API HTTPS — caller should surface this.
        return None
    if ptype == "outbound":
        if not str(proxy.get("outbound") or "").strip():
            return None
        return {
            "type": "socks5",
            "host": "127.0.0.1",
            "port": TG_LOCAL_SOCKS_PORT,
            "user": "",
            "password": "",
            "via": "outbound",
            "outbound": str(proxy.get("outbound") or "").strip(),
        }
    # Prefer explicit URL when set
    url = str(proxy.get("url") or "").strip()
    if url:
        parsed = parse_proxy_url(url)
        if parsed.get("host"):
            return {
                "type": parsed.get("type") or ptype,
                "host": parsed["host"],
                "port": int(parsed.get("port") or 0),
                "user": parsed.get("user") or "",
                "password": parsed.get("password") or "",
            }
    host = str(proxy.get("host") or "").strip()
    port = int(proxy.get("port") or 0)
    if not host or port <= 0:
        return None
    return {
        "type": ptype if ptype in ("http", "socks5", "socks4") else "socks5",
        "host": host,
        "port": port,
        "user": str(proxy.get("user") or "").strip(),
        "password": str(proxy.get("password") or ""),
    }


def build_opener(settings: dict) -> urllib.request.OpenerDirector:
    """urllib opener that sends all Telegram HTTPS via the configured proxy."""
    ep = proxy_endpoint(settings)
    if not ep:
        return urllib.request.build_opener()
    ptype = ep["type"]
    host, port = ep["host"], int(ep["port"])
    user, password = ep.get("user") or None, ep.get("password") or None
    if ptype == "http":
        auth = ""
        if user:
            auth = f"{urllib.parse.quote(user)}:{urllib.parse.quote(password or '')}@"
        proxy_url = f"http://{auth}{host}:{port}"
        return urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}),
        )
    try:
        import socks
        from sockshandler import SocksiPyHandler
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("Для SOCKS-прокси установите PySocks (pip install PySocks)") from exc
    kind = socks.SOCKS5 if ptype != "socks4" else socks.SOCKS4
    return urllib.request.build_opener(
        SocksiPyHandler(kind, host, port, username=user, password=password),
    )


def needs_xray_socks(settings: dict) -> bool:
    proxy = (settings or {}).get("proxy") or {}
    return bool(
        proxy.get("enabled")
        and str(proxy.get("type") or "").lower() == "outbound"
        and str(proxy.get("outbound") or "").strip()
    )


def escape(text: str) -> str:
    return html.escape(str(text or ""), quote=False)


def user_profile(from_user: dict | None, *, fallback_id: str | int = "") -> dict:
    """Normalize Telegram message.from into {id, username, first_name, last_name, fio, display}."""
    u = from_user or {}
    uid = str(u.get("id") or fallback_id or "").strip()
    username = str(u.get("username") or "").strip().lstrip("@")
    first = str(u.get("first_name") or "").strip()
    last = str(u.get("last_name") or "").strip()
    fio = " ".join(x for x in (first, last) if x).strip()
    display = fio or (f"@{username}" if username else uid) or "—"
    return {
        "id": uid,
        "username": username,
        "first_name": first,
        "last_name": last,
        "fio": fio,
        "display": display,
    }


class Bot:
    """Thread-safe-ish wrapper; `hooks` supply data from the panel without import cycles."""

    def __init__(self, get_settings: Callable[[], dict], hooks: dict[str, Callable],
                 *, should_poll: Callable[[], bool] | None = None):
        self.get_settings = get_settings
        self.hooks = hooks
        # Optional gate: only one node in a cluster should long-poll (usually master)
        self.should_poll = should_poll or (lambda: True)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._offset = 0
        self._last_report = time.time()
        self._last_backup = time.time()
        self._last_cpu_alert = 0.0
        self._username: str = ""
        self._username_checked: float = 0.0
        self._webhook_cleared = False

    # ------------------------------------------------------------ transport
    def _opener(self) -> urllib.request.OpenerDirector:
        return build_opener(self.get_settings())

    def _call(self, method: str, params: dict | None = None, timeout: int = 30) -> dict:
        s = self.get_settings()
        if not s.get("token"):
            return {"ok": False, "error": "no token"}
        proxy = s.get("proxy") or {}
        if proxy.get("enabled") and str(proxy.get("type") or "").lower() in ("mtproto", "mtproxy", "tg"):
            return {
                "ok": False,
                "error": "MTProto-прокси нельзя использовать для Bot API — выберите HTTP, SOCKS5 или outbound (VLESS)",
            }
        data = urllib.parse.urlencode(params or {}).encode()
        req = urllib.request.Request(API.format(token=s["token"], method=method), data=data)
        try:
            with self._opener().open(req, timeout=timeout) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as exc:
            body = ""
            try:
                body = exc.read().decode("utf-8", "replace")[:500]
            except Exception:
                pass
            try:
                parsed = json.loads(body) if body else {}
            except json.JSONDecodeError:
                parsed = {}
            err = str(parsed.get("description") or body or f"HTTP {exc.code}")
            return {"ok": False, "error": err, "status": exc.code, "description": err}
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": str(exc)}

    def username(self) -> str:
        """Bot @username from getMe (cached ~1h). Empty if bot disabled / unreachable."""
        s = self.get_settings()
        if not s.get("enabled") or not s.get("token"):
            self._username = ""
            return ""
        now = time.time()
        if self._username and now - self._username_checked < 3600:
            return self._username
        res = self._call("getMe", timeout=15)
        user = (res.get("result") or {}) if res.get("ok") else {}
        self._username = str(user.get("username") or "")
        self._username_checked = now
        return self._username

    def deep_link(self, payload: str) -> str:
        name = self.username()
        if not name:
            return ""
        return f"https://t.me/{name}?start={urllib.parse.quote(payload)}"

    def send(self, text: str, chat_id: str | int | None = None) -> bool:
        s = self.get_settings()
        if not s.get("enabled") or not s.get("token"):
            return False
        targets = [chat_id] if chat_id is not None else (s.get("admin_ids") or [])
        ok_any = False
        for cid in targets:
            if cid is None or cid == "":
                continue
            # Prefer HTML; on Telegram 400 fall back to plain text
            res = self._call("sendMessage", {
                "chat_id": cid,
                "text": text[:4000],
                "parse_mode": "HTML",
                "disable_web_page_preview": "true",
            })
            if not res.get("ok"):
                plain = text.replace("<b>", "").replace("</b>", "").replace("<code>", "").replace("</code>", "")
                plain = plain.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
                res = self._call("sendMessage", {
                    "chat_id": cid,
                    "text": plain[:4000],
                    "disable_web_page_preview": "true",
                })
            if res.get("ok"):
                ok_any = True
            else:
                log.warning("sendMessage failed chat=%s: %s", cid, res.get("error") or res.get("description"))
        return ok_any

    def send_document(self, filename: str, blob: bytes, caption: str = "", chat_id: str | int | None = None) -> bool:
        """Send a document to admin chat(s). Returns True if at least one delivery succeeded."""
        s = self.get_settings()
        if not s.get("enabled") or not s.get("token"):
            return False
        ok_any = False
        for cid in ([chat_id] if chat_id is not None else (s.get("admin_ids") or [])):
            if cid is None or cid == "":
                continue
            boundary = uuid.uuid4().hex
            parts = []
            for k, v in (("chat_id", str(cid)), ("caption", caption)):
                parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n".encode())
            parts.append(
                f"--{boundary}\r\nContent-Disposition: form-data; name=\"document\"; filename=\"{filename}\"\r\n"
                "Content-Type: application/octet-stream\r\n\r\n".encode() + blob + b"\r\n"
            )
            parts.append(f"--{boundary}--\r\n".encode())
            req = urllib.request.Request(
                API.format(token=s["token"], method="sendDocument"),
                data=b"".join(parts),
                headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            )
            try:
                raw = self._opener().open(req, timeout=120).read()
                try:
                    parsed = json.loads(raw.decode("utf-8", "replace") or "{}")
                except json.JSONDecodeError:
                    parsed = {}
                if parsed.get("ok"):
                    ok_any = True
                else:
                    log.warning(
                        "sendDocument failed chat=%s: %s",
                        cid, parsed.get("description") or parsed.get("error") or raw[:200],
                    )
            except Exception as exc:  # noqa: BLE001
                log.warning("sendDocument failed chat=%s: %s", cid, exc)
        return ok_any

    # ------------------------------------------------------------ lifecycle
    def start(self) -> None:
        """Start or restart the polling thread."""
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._webhook_cleared = False
        self._thread = threading.Thread(target=self._loop, name="l2x-tgbot", daemon=True)
        self._thread.start()
        log.info("tgbot thread started")

    def restart(self) -> None:
        """Force restart after settings change (token / enabled / admin_ids)."""
        self.stop()
        # Give previous long-poll a moment to exit
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
        self._thread = None
        self._offset = 0
        self._username = ""
        self._username_checked = 0.0
        self.start()

    def stop(self) -> None:
        self._stop.set()

    def _is_admin(self, chat_id) -> bool:
        admins = {str(x).strip() for x in (self.get_settings().get("admin_ids") or []) if str(x).strip()}
        return str(chat_id).strip() in admins

    def _ensure_polling_mode(self) -> None:
        if self._webhook_cleared:
            return
        res = self._call("deleteWebhook", {"drop_pending_updates": "false"}, timeout=15)
        if res.get("ok") or "Webhook is already deleted" in str(res.get("description") or ""):
            self._webhook_cleared = True
            log.info("telegram webhook cleared for long-polling")
        else:
            log.warning("deleteWebhook: %s", res.get("error") or res.get("description"))

    def _loop(self) -> None:
        while not self._stop.is_set():
            s = self.get_settings()
            if not s.get("enabled") or not s.get("token"):
                self._stop.wait(5)
                continue
            # Scheduled report/CPU still run on master even when command long-poll is off.
            # (Backup schedule lives in the panel backup loop — write → TG → delete file.)
            if not self.should_poll() or s.get("receive_commands", True) is False:
                try:
                    self._periodic(include_backup=False)
                except Exception:
                    log.exception("periodic failed")
                self._stop.wait(10)
                continue
            self._ensure_polling_mode()
            # Short long-poll: some hosts RST 25s holds to api.telegram.org
            res = self._call("getUpdates", {"offset": self._offset, "timeout": 8}, timeout=20)
            if res.get("status") == 409:
                # Another process is polling this token — back off
                log.warning("getUpdates 409 Conflict — another poller has this token")
                self._stop.wait(15)
                continue
            for upd in res.get("result") or []:
                self._offset = int(upd.get("update_id") or 0) + 1
                msg = upd.get("message") or upd.get("edited_message") or {}
                text = (msg.get("text") or "").strip()
                chat_id = (msg.get("chat") or {}).get("id")
                from_user = msg.get("from") if isinstance(msg.get("from"), dict) else {}
                if text and chat_id is not None:
                    try:
                        self._handle(chat_id, text, from_user=from_user)
                    except Exception as exc:  # noqa: BLE001
                        log.exception("handle failed")
                        self.send(f"Ошибка: {escape(exc)}", chat_id)
            try:
                self._periodic(include_backup=False)
            except Exception:
                log.exception("periodic failed")
            if not res.get("ok"):
                err = res.get("error") or res.get("description") or "getUpdates failed"
                log.warning("getUpdates: %s", err)
                # Network blips (RST / timeout) — brief pause then retry
                self._stop.wait(2)
            else:
                # Tiny yield so a tight timeout=0 style loop cannot spin CPU
                self._stop.wait(0.2)

    def _periodic(self, *, include_backup: bool = False) -> None:
        if not self.should_poll():
            return
        s = self.get_settings()
        now = time.time()
        if s.get("report_hours") and now - self._last_report >= float(s["report_hours"]) * 3600:
            self._last_report = now
            self.send(self.hooks["report"]())
        # Scheduled backups are handled by panel `_tg_backup_loop` (disk → TG → delete).
        # Optional legacy path kept for hooks/tests when include_backup=True.
        if include_backup and s.get("backup_hours") and now - self._last_backup >= float(s["backup_hours"]) * 3600:
            self._last_backup = now
            hook = self.hooks.get("backup_send") or self.hooks.get("backup")
            if callable(hook):
                try:
                    hook()
                except Exception:
                    log.exception("scheduled backup hook failed")
        cpu = self.hooks["cpu"]()
        if s.get("cpu_threshold") and cpu >= float(s["cpu_threshold"]) and now - self._last_cpu_alert > 1800:
            self._last_cpu_alert = now
            self.send(f"⚠️ CPU {cpu:.0f}% (порог {s['cpu_threshold']}%)")

    # ------------------------------------------------------------ commands
    def _handle(self, chat_id, text: str, *, from_user: dict | None = None) -> None:
        cmd, _, arg = text.partition(" ")
        cmd = cmd.split("@")[0].lower()
        arg = arg.strip()
        chat = str(chat_id)
        is_admin = self._is_admin(chat_id)
        profile = user_profile(from_user or {}, fallback_id=chat)

        # Keep linked client profile fresh on any message
        try:
            self.hooks.get("touch_tg_profile", lambda *_a, **_k: None)(chat, profile)
        except Exception:
            pass

        if cmd == "/start":
            if arg.startswith("bind_"):
                _ok, msg = self.hooks["bind_tg"](arg[5:], chat, profile)
                self.send(msg, chat_id)
                return
            linked = self.hooks["client_by_tg"](chat)
            if is_admin:
                admins = self.get_settings().get("admin_ids") or []
                self.send(
                    f"Админ-бот L2X. Ваш chat id: <code>{escape(chat_id)}</code>\n"
                    f"Профиль: {escape(profile.get('display') or '—')}\n"
                    f"Админов в настройках: <b>{len(admins)}</b>\n"
                    "Команды: /help /status /online /clients /usage /backup /restart_xray /admins",
                    chat_id,
                )
                return
            if linked:
                self.send(
                    "✅ Подписка привязана.\n\n" + linked
                    + "\n\nКоманды: /status — трафик и срок · /unlink — отвязать",
                    chat_id,
                )
            else:
                self.send(
                    f"Ваш chat id: <code>{escape(chat_id)}</code>\n"
                    f"Профиль: {escape(profile.get('display') or '—')}\n"
                    "Привяжите аккаунт на странице подписки (кнопка Telegram) "
                    "или добавьте id в карточку клиента / в Настройки → Telegram (админ).",
                    chat_id,
                )
            return

        if cmd == "/id":
            self.send(
                f"Chat id: <code>{escape(chat_id)}</code>\n"
                f"Username: <code>{escape(profile.get('username') or '—')}</code>\n"
                f"Имя: {escape(profile.get('fio') or '—')}",
                chat_id,
            )
            return

        if cmd == "/unlink":
            _ok, msg = self.hooks["unlink_tg"](chat)
            self.send(msg, chat_id)
            return

        if not is_admin:
            if cmd in ("/status", "/sub", "/help") or not cmd.startswith("/"):
                client_info = self.hooks["client_by_tg"](chat)
                if client_info:
                    self.send(client_info + "\n\n/status · /unlink", chat_id)
                else:
                    self.send(
                        "Подписка не привязана. Откройте страницу подписки в браузере "
                        "и нажмите «Привязать Telegram».\nВаш id: <code>"
                        + escape(chat) + "</code>",
                        chat_id,
                    )
                return
            self.send("Нет доступа. Ваш id: <code>" + escape(chat) + "</code>", chat_id)
            return

        if cmd == "/help":
            self.send(
                "/status — состояние сервера\n/online — клиенты онлайн\n/usage email — трафик клиента\n"
                "/clients — список клиентов\n/backup — бэкап\n"
                "/restart_xray — перезапуск Xray\n/report — отчёт\n"
                "/admins — список admin chat id\n/id — ваш chat id / username / имя",
                chat_id,
            )
        elif cmd == "/admins":
            admins = [str(x).strip() for x in (self.get_settings().get("admin_ids") or []) if str(x).strip()]
            if not admins:
                self.send("Список админов пуст. Добавьте chat id в Настройки → Telegram (по одному на строку).", chat_id)
            else:
                lines = "\n".join(f"• <code>{escape(a)}</code>" for a in admins)
                self.send(f"Админы бота ({len(admins)}):\n{lines}", chat_id)
        elif cmd == "/status" or cmd == "/report":
            self.send(self.hooks["report"](), chat_id)
        elif cmd == "/online":
            self.send(self.hooks["online"]() or "Никого онлайн", chat_id)
        elif cmd == "/usage":
            self.send(self.hooks["usage"](arg) if arg else "Формат: /usage email", chat_id)
        elif cmd == "/clients":
            self.send(self.hooks["clients"](), chat_id)
        elif cmd == "/backup":
            hook = self.hooks.get("backup_send")
            if callable(hook):
                res = hook()
                if isinstance(res, dict) and res.get("ok"):
                    self.send(
                        f"Бэкап отправлен ({escape(res.get('name') or '')}) и удалён с сервера.",
                        chat_id,
                    )
                else:
                    err = (res or {}).get("error") if isinstance(res, dict) else "ошибка"
                    self.send(f"Бэкап: {escape(err)}", chat_id)
            else:
                name, blob = self.hooks["backup"]()
                ok = self.send_document(name, blob, "Бэкап L2X Panel", chat_id)
                self.send("Бэкап отправлен." if ok else "Не удалось отправить бэкап.", chat_id)
        elif cmd == "/restart_xray":
            self.send(self.hooks["restart_xray"](), chat_id)
        else:
            self.send("Неизвестная команда. /help", chat_id)
