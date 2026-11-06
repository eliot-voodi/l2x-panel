"""Telegram bot: admin notifications, reports, backups and lookup commands (long polling)."""
from __future__ import annotations

import json
import threading
import time
import urllib.parse
import urllib.request
import uuid
from typing import Callable

API = "https://api.telegram.org/bot{token}/{method}"


def default_settings() -> dict:
    return {
        "enabled": False,
        "token": "",
        "admin_ids": [],
        "notify_login": True,
        "notify_quota": True,
        "notify_expire_days": 3,
        "notify_iplimit": True,
        "notify_tunnel": True,
        "cpu_threshold": 85,
        "report_hours": 24,
        "backup_hours": 24,
    }


class Bot:
    """Thread-safe-ish wrapper; `hooks` supply data from the panel without import cycles."""

    def __init__(self, get_settings: Callable[[], dict], hooks: dict[str, Callable]):
        self.get_settings = get_settings
        self.hooks = hooks
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._offset = 0
        self._last_report = time.time()
        self._last_backup = time.time()
        self._last_cpu_alert = 0.0
        self._username: str = ""
        self._username_checked: float = 0.0

    # ------------------------------------------------------------ transport
    def _call(self, method: str, params: dict | None = None, timeout: int = 30) -> dict:
        s = self.get_settings()
        if not s.get("token"):
            return {"ok": False}
        data = urllib.parse.urlencode(params or {}).encode()
        req = urllib.request.Request(API.format(token=s["token"], method=method), data=data)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read())
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

    def send(self, text: str, chat_id: str | int | None = None) -> None:
        s = self.get_settings()
        if not s.get("enabled") or not s.get("token"):
            return
        targets = [chat_id] if chat_id else s.get("admin_ids") or []
        for cid in targets:
            self._call("sendMessage", {"chat_id": cid, "text": text[:4000], "parse_mode": "HTML", "disable_web_page_preview": "true"})

    def send_document(self, filename: str, blob: bytes, caption: str = "", chat_id: str | int | None = None) -> None:
        s = self.get_settings()
        if not s.get("enabled") or not s.get("token"):
            return
        for cid in ([chat_id] if chat_id else s.get("admin_ids") or []):
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
                urllib.request.urlopen(req, timeout=60).read()
            except Exception:
                pass

    # ------------------------------------------------------------ lifecycle
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="l2x-tgbot", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _is_admin(self, chat_id) -> bool:
        return str(chat_id) in {str(x) for x in self.get_settings().get("admin_ids") or []}

    def _loop(self) -> None:
        while not self._stop.is_set():
            s = self.get_settings()
            if not s.get("enabled") or not s.get("token"):
                self._stop.wait(15)
                continue
            res = self._call("getUpdates", {"offset": self._offset, "timeout": 25}, timeout=35)
            for upd in res.get("result") or []:
                self._offset = upd["update_id"] + 1
                msg = upd.get("message") or {}
                text = (msg.get("text") or "").strip()
                chat_id = (msg.get("chat") or {}).get("id")
                if text and chat_id:
                    try:
                        self._handle(chat_id, text)
                    except Exception as exc:  # noqa: BLE001
                        self.send(f"Ошибка: {exc}", chat_id)
            self._periodic()
            if not res.get("ok"):
                self._stop.wait(10)

    def _periodic(self) -> None:
        s = self.get_settings()
        now = time.time()
        if s.get("report_hours") and now - self._last_report >= float(s["report_hours"]) * 3600:
            self._last_report = now
            self.send(self.hooks["report"]())
        if s.get("backup_hours") and now - self._last_backup >= float(s["backup_hours"]) * 3600:
            self._last_backup = now
            name, blob = self.hooks["backup"]()
            self.send_document(name, blob, "Автоматический бэкап L2X Panel")
        cpu = self.hooks["cpu"]()
        if s.get("cpu_threshold") and cpu >= float(s["cpu_threshold"]) and now - self._last_cpu_alert > 1800:
            self._last_cpu_alert = now
            self.send(f"⚠️ CPU {cpu:.0f}% (порог {s['cpu_threshold']}%)")

    # ------------------------------------------------------------ commands
    def _handle(self, chat_id, text: str) -> None:
        cmd, _, arg = text.partition(" ")
        cmd = cmd.split("@")[0].lower()
        arg = arg.strip()
        chat = str(chat_id)

        if cmd == "/start":
            if arg.startswith("bind_"):
                _ok, msg = self.hooks["bind_tg"](arg[5:], chat)
                self.send(msg, chat_id)
                return
            linked = self.hooks["client_by_tg"](chat)
            if linked:
                self.send(
                    "✅ Подписка привязана.\n\n" + linked
                    + "\n\nКоманды: /status — трафик и срок · /unlink — отвязать",
                    chat_id,
                )
            else:
                self.send(
                    f"Ваш chat id: <code>{chat_id}</code>\n"
                    "Привяжите аккаунт на странице подписки (кнопка Telegram) "
                    "или добавьте id в карточку клиента / в Настройки → Telegram (админ).",
                    chat_id,
                )
            return

        if cmd == "/id":
            self.send(f"Ваш chat id: <code>{chat_id}</code>", chat_id)
            return

        if cmd == "/unlink":
            _ok, msg = self.hooks["unlink_tg"](chat)
            self.send(msg, chat_id)
            return

        if not self._is_admin(chat_id):
            if cmd in ("/status", "/sub", "/help") or not cmd.startswith("/"):
                client_info = self.hooks["client_by_tg"](chat)
                if client_info:
                    self.send(client_info + "\n\n/status · /unlink", chat_id)
                else:
                    self.send(
                        "Подписка не привязана. Откройте страницу подписки в браузере "
                        "и нажмите «Привязать Telegram».\nВаш id: <code>"
                        + chat + "</code>",
                        chat_id,
                    )
                return
            self.send("Нет доступа. Ваш id: " + chat, chat_id)
            return

        if cmd == "/help":
            self.send(
                "/status — состояние сервера\n/online — клиенты онлайн\n/usage email — трафик клиента\n"
                "/clients — список клиентов\n/tunnels — L2TP туннели\n/backup — бэкап\n"
                "/restart_xray — перезапуск Xray\n/report — отчёт", chat_id)
        elif cmd == "/status" or cmd == "/report":
            self.send(self.hooks["report"](), chat_id)
        elif cmd == "/online":
            self.send(self.hooks["online"]() or "Никого онлайн", chat_id)
        elif cmd == "/usage":
            self.send(self.hooks["usage"](arg) if arg else "Формат: /usage email", chat_id)
        elif cmd == "/clients":
            self.send(self.hooks["clients"](), chat_id)
        elif cmd == "/tunnels":
            self.send(self.hooks["tunnels"](), chat_id)
        elif cmd == "/backup":
            name, blob = self.hooks["backup"]()
            self.send_document(name, blob, "Бэкап L2X Panel", chat_id)
        elif cmd == "/restart_xray":
            self.send(self.hooks["restart_xray"](), chat_id)
        else:
            self.send("Неизвестная команда. /help", chat_id)
